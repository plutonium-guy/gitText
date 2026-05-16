#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;
use core::ptr;
use core::slice;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// ============================================================================
// HEAP / MEMORY MANAGEMENT
// ============================================================================

const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0u8; HEAP_SIZE]);
static mut HEAP_OFFSET: usize = 0;

#[inline]
unsafe fn heap_base() -> *mut u8 {
    (&raw mut HEAP.0) as *mut u8
}

#[inline]
unsafe fn alloc_inline(size: usize) -> *mut u8 {
    let aligned = (size + 7) & !7usize;
    let off = HEAP_OFFSET;
    if off + aligned > HEAP_SIZE {
        return ptr::null_mut();
    }
    HEAP_OFFSET = off + aligned;
    heap_base().add(off)
}

#[no_mangle]
pub unsafe extern "C" fn alloc(size: usize) -> *mut u8 {
    alloc_inline(size)
}

#[no_mangle]
pub unsafe extern "C" fn free(_ptr: *mut u8, _size: usize) {}

#[no_mangle]
pub unsafe extern "C" fn reset_heap() {
    HEAP_OFFSET = 0;
}

#[no_mangle]
pub unsafe extern "C" fn get_heap_used() -> usize {
    HEAP_OFFSET
}

#[no_mangle]
pub unsafe extern "C" fn get_heap_size() -> usize {
    HEAP_SIZE
}

#[inline]
fn pack(p: *const u8, len: usize) -> u64 {
    ((p as usize as u64) << 32) | (len as u64)
}

#[no_mangle]
pub extern "C" fn get_ptr(result: u64) -> usize {
    (result >> 32) as usize
}

#[no_mangle]
pub extern "C" fn get_len(result: u64) -> usize {
    (result & 0xFFFF_FFFF) as usize
}

// ============================================================================
// LZSS COMPRESSION
// ============================================================================

const WINDOW_SIZE: usize = 4096;
const WINDOW_MASK: usize = WINDOW_SIZE - 1;
const MIN_MATCH_LEN: usize = 3;
const MAX_MATCH_LEN: usize = 18;
const HASH_SIZE: usize = 4096;
const HASH_MASK: usize = HASH_SIZE - 1;

static mut HASH_HEAD: [i32; HASH_SIZE] = [-1; HASH_SIZE];
static mut HASH_PREV: [i32; WINDOW_SIZE] = [-1; WINDOW_SIZE];

#[inline]
fn hash3(data: &[u8], pos: usize) -> usize {
    if pos + 2 >= data.len() {
        return 0;
    }
    let h = (data[pos] as usize) << 10
        ^ (data[pos + 1] as usize) << 5
        ^ (data[pos + 2] as usize);
    h & HASH_MASK
}

unsafe fn reset_hash_chains() {
    let head = &raw mut HASH_HEAD;
    for i in 0..HASH_SIZE {
        (*head)[i] = -1;
    }
    let prev = &raw mut HASH_PREV;
    for i in 0..WINDOW_SIZE {
        (*prev)[i] = -1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn compress(input_ptr: *const u8, input_len: usize) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let max_output = input_len + (input_len >> 3) + 16;
    let out_ptr = alloc_inline(max_output);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, max_output);

    reset_hash_chains();

    let mut out_pos: usize = 0;
    let mut in_pos: usize = 0;
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u32 = 0;

    while in_pos < input_len {
        let mut best_offset: usize = 0;
        let mut best_len: usize = 0;

        if in_pos + MIN_MATCH_LEN <= input_len {
            let h = hash3(input, in_pos);
            let mut chain_pos = HASH_HEAD[h];
            let max_match = MAX_MATCH_LEN.min(input_len - in_pos);
            let mut chain_limit: usize = 128;

            while chain_pos >= 0 && chain_limit > 0 {
                let pos = chain_pos as usize;
                let dist = in_pos - pos;
                if dist > WINDOW_SIZE {
                    break;
                }
                if best_len >= max_match {
                    break;
                }
                if input[pos] == input[in_pos]
                    && input[pos + best_len] == input[in_pos + best_len]
                {
                    let mut match_len = 0usize;
                    while match_len < max_match
                        && input[pos + match_len] == input[in_pos + match_len]
                    {
                        match_len += 1;
                    }
                    if match_len > best_len {
                        best_len = match_len;
                        best_offset = dist;
                        if best_len >= MAX_MATCH_LEN {
                            break;
                        }
                    }
                }
                chain_pos = HASH_PREV[pos & WINDOW_MASK];
                chain_limit -= 1;
            }

            HASH_PREV[in_pos & WINDOW_MASK] = HASH_HEAD[h];
            HASH_HEAD[h] = in_pos as i32;
        }

        if best_len >= MIN_MATCH_LEN {
            let bits: u32 = 1
                | ((best_offset - 1) as u32 & 0xFFF) << 1
                | ((best_len - MIN_MATCH_LEN) as u32 & 0xF) << 13;
            bit_buffer |= bits << bit_count;
            bit_count += 17;

            while bit_count >= 8 {
                if out_pos < max_output {
                    output[out_pos] = bit_buffer as u8;
                    out_pos += 1;
                }
                bit_buffer >>= 8;
                bit_count -= 8;
            }

            let mut skip = 1usize;
            while skip < best_len && in_pos + skip + 2 < input_len {
                let sh = hash3(input, in_pos + skip);
                HASH_PREV[(in_pos + skip) & WINDOW_MASK] = HASH_HEAD[sh];
                HASH_HEAD[sh] = (in_pos + skip) as i32;
                skip += 1;
            }

            in_pos += best_len;
        } else {
            let bits: u32 = (input[in_pos] as u32) << 1;
            bit_buffer |= bits << bit_count;
            bit_count += 9;

            while bit_count >= 8 {
                if out_pos < max_output {
                    output[out_pos] = bit_buffer as u8;
                    out_pos += 1;
                }
                bit_buffer >>= 8;
                bit_count -= 8;
            }

            in_pos += 1;
        }
    }

    if bit_count > 0 && out_pos < max_output {
        output[out_pos] = bit_buffer as u8;
        out_pos += 1;
    }

    pack(out_ptr, out_pos)
}

#[no_mangle]
pub unsafe extern "C" fn decompress(input_ptr: *const u8, input_len: usize) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let max_output = input_len * 12;
    let out_ptr = alloc_inline(max_output);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, max_output);

    let mut out_pos: usize = 0;
    let mut in_pos: usize = 0;
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u32 = 0;

    while bit_count < 24 && in_pos < input_len {
        bit_buffer |= (input[in_pos] as u32) << bit_count;
        bit_count += 8;
        in_pos += 1;
    }

    while bit_count > 0 || in_pos < input_len {
        while bit_count < 17 && in_pos < input_len {
            bit_buffer |= (input[in_pos] as u32) << bit_count;
            bit_count += 8;
            in_pos += 1;
        }

        if bit_count == 0 {
            break;
        }

        let flag = bit_buffer & 1;
        bit_buffer >>= 1;
        bit_count -= 1;

        if flag == 0 {
            if bit_count < 8 {
                if in_pos >= input_len {
                    break;
                }
                bit_buffer |= (input[in_pos] as u32) << bit_count;
                bit_count += 8;
                in_pos += 1;
            }
            if out_pos < max_output {
                output[out_pos] = bit_buffer as u8;
                out_pos += 1;
            }
            bit_buffer >>= 8;
            bit_count -= 8;
        } else {
            while bit_count < 16 && in_pos < input_len {
                bit_buffer |= (input[in_pos] as u32) << bit_count;
                bit_count += 8;
                in_pos += 1;
            }
            let offset = ((bit_buffer & 0xFFF) as usize) + 1;
            bit_buffer >>= 12;
            let length = ((bit_buffer & 0xF) as usize) + MIN_MATCH_LEN;
            bit_buffer >>= 4;
            bit_count -= 16;

            if out_pos < offset {
                break;
            }
            let src_start = out_pos - offset;
            let mut i = 0usize;
            while i < length && out_pos < max_output {
                output[out_pos] = output[src_start + i];
                out_pos += 1;
                i += 1;
            }
        }
    }

    pack(out_ptr, out_pos)
}

// ============================================================================
// BASE64URL ENCODE / DECODE
// ============================================================================

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64URL_DECODE_TABLE: [u8; 256] = {
    let mut t = [255u8; 256];
    let mut i = 0;
    while i < 64 {
        t[BASE64URL_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
};

#[no_mangle]
pub unsafe extern "C" fn base64url_encode(input_ptr: *const u8, input_len: usize) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let output_len = (input_len * 4 + 2) / 3;
    let out_ptr = alloc_inline(output_len);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, output_len);

    let mut out_pos = 0usize;
    let chunks = input_len / 3;
    let mut c = 0usize;
    while c < chunks {
        let idx = c * 3;
        let b0 = input[idx];
        let b1 = input[idx + 1];
        let b2 = input[idx + 2];
        output[out_pos] = BASE64URL_ALPHABET[(b0 >> 2) as usize];
        output[out_pos + 1] = BASE64URL_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
        output[out_pos + 2] = BASE64URL_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize];
        output[out_pos + 3] = BASE64URL_ALPHABET[(b2 & 0x3f) as usize];
        out_pos += 4;
        c += 1;
    }

    let i = chunks * 3;
    if i < input_len {
        let b0 = input[i];
        output[out_pos] = BASE64URL_ALPHABET[(b0 >> 2) as usize];
        out_pos += 1;
        if i + 1 < input_len {
            let b1 = input[i + 1];
            output[out_pos] = BASE64URL_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
            output[out_pos + 1] = BASE64URL_ALPHABET[((b1 & 0x0f) << 2) as usize];
            out_pos += 2;
        } else {
            output[out_pos] = BASE64URL_ALPHABET[((b0 & 0x03) << 4) as usize];
            out_pos += 1;
        }
    }

    pack(out_ptr, out_pos)
}

#[no_mangle]
pub unsafe extern "C" fn base64url_decode(input_ptr: *const u8, input_len: usize) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let output_len = (input_len * 3) / 4 + 1;
    let out_ptr = alloc_inline(output_len);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, output_len);

    let mut out_pos = 0usize;
    let mut i = 0usize;

    while i + 4 <= input_len {
        let c0 = BASE64URL_DECODE_TABLE[input[i] as usize];
        let c1 = BASE64URL_DECODE_TABLE[input[i + 1] as usize];
        let c2 = BASE64URL_DECODE_TABLE[input[i + 2] as usize];
        let c3 = BASE64URL_DECODE_TABLE[input[i + 3] as usize];

        if c0 == 255 || c1 == 255 {
            break;
        }
        output[out_pos] = (c0 << 2) | (c1 >> 4);
        out_pos += 1;

        if c2 != 255 {
            output[out_pos] = ((c1 & 0x0f) << 4) | (c2 >> 2);
            out_pos += 1;
            if c3 != 255 {
                output[out_pos] = ((c2 & 0x03) << 6) | c3;
                out_pos += 1;
            }
        }
        i += 4;
    }

    if i < input_len {
        let c0 = BASE64URL_DECODE_TABLE[input[i] as usize];
        if c0 != 255 && i + 1 < input_len {
            let c1 = BASE64URL_DECODE_TABLE[input[i + 1] as usize];
            if c1 != 255 {
                output[out_pos] = (c0 << 2) | (c1 >> 4);
                out_pos += 1;
                if i + 2 < input_len {
                    let c2 = BASE64URL_DECODE_TABLE[input[i + 2] as usize];
                    if c2 != 255 {
                        output[out_pos] = ((c1 & 0x0f) << 4) | (c2 >> 2);
                        out_pos += 1;
                    }
                }
            }
        }
    }

    pack(out_ptr, out_pos)
}

// ============================================================================
// AES-256-CTR
// ============================================================================

const AES_KEY_SIZE: usize = 32;
const AES_ROUNDS: usize = 14;

const fn rotl8(x: u8, r: u32) -> u8 {
    (x << r) | (x >> (8 - r))
}

const SBOX: [u8; 256] = {
    let mut s = [0u8; 256];
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    s[0] = 0x63;
    loop {
        let pl = p << 1;
        let mix = if (p & 0x80) != 0 { 0x1B } else { 0 };
        p = p ^ pl ^ mix;

        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if (q & 0x80) != 0 { 0x09 } else { 0 };

        let xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        s[p as usize] = xformed ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s
};

const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn aes_key_expansion(key: &[u8], round_keys: &mut [u8; 240]) {
    let mut i = 0usize;
    while i < AES_KEY_SIZE {
        round_keys[i] = key[i];
        i += 1;
    }

    let mut rcon_idx = 1usize;
    while i < 240 {
        let mut temp = [0u8; 4];
        for j in 0..4 {
            temp[j] = round_keys[i - 4 + j];
        }

        if i % AES_KEY_SIZE == 0 {
            let t = temp[0];
            temp[0] = SBOX[temp[1] as usize] ^ RCON[rcon_idx];
            temp[1] = SBOX[temp[2] as usize];
            temp[2] = SBOX[temp[3] as usize];
            temp[3] = SBOX[t as usize];
            rcon_idx += 1;
        } else if i % AES_KEY_SIZE == 16 {
            for j in 0..4 {
                temp[j] = SBOX[temp[j] as usize];
            }
        }

        for j in 0..4 {
            round_keys[i + j] = round_keys[i - AES_KEY_SIZE + j] ^ temp[j];
        }
        i += 4;
    }
}

#[inline]
fn gmul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;
    let mut i = 0;
    while i < 8 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let hi = aa & 0x80;
        aa <<= 1;
        if hi != 0 {
            aa ^= 0x1B;
        }
        bb >>= 1;
        i += 1;
    }
    result
}

fn aes_encrypt_block(input: &[u8; 16], output: &mut [u8; 16], round_keys: &[u8; 240]) {
    let mut state = [0u8; 16];
    for i in 0..16 {
        state[i] = input[i] ^ round_keys[i];
    }

    let mut round = 1usize;
    while round < AES_ROUNDS {
        for i in 0..16 {
            state[i] = SBOX[state[i] as usize];
        }

        let t1 = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = t1;

        let t2 = state[2];
        let t6 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = t2;
        state[14] = t6;

        let t3 = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = t3;

        for col in 0..4 {
            let c = col * 4;
            let a0 = state[c];
            let a1 = state[c + 1];
            let a2 = state[c + 2];
            let a3 = state[c + 3];
            state[c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            state[c + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            state[c + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            state[c + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }

        let rk = round * 16;
        for i in 0..16 {
            state[i] ^= round_keys[rk + i];
        }
        round += 1;
    }

    for i in 0..16 {
        state[i] = SBOX[state[i] as usize];
    }
    let t1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t1;

    let t2 = state[2];
    let t6 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t2;
    state[14] = t6;

    let t3 = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t3;

    let rk = AES_ROUNDS * 16;
    for i in 0..16 {
        output[i] = state[i] ^ round_keys[rk + i];
    }
}

fn derive_key(password: &[u8], salt: &[u8], key: &mut [u8; 32]) {
    let mut state = [0u8; 32];
    for i in 0..32 {
        state[i] = if i < salt.len() {
            salt[i]
        } else {
            i as u8
        };
    }

    let mut round = 0usize;
    while round < 1000 {
        for (i, &p) in password.iter().enumerate() {
            let idx = (i + round) % 32;
            state[idx] ^= p;
            state[idx] = SBOX[state[idx] as usize];
            state[(idx + 1) % 32] ^= state[idx];
        }
        let mut tmp = [0u8; 32];
        for i in 0..32 {
            tmp[i] = state[i] ^ state[(i + 13) % 32] ^ state[(i + 23) % 32];
        }
        state = tmp;
        round += 1;
    }
    *key = state;
}

#[no_mangle]
pub unsafe extern "C" fn aes_ctr_encrypt(
    data_ptr: *const u8,
    data_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
) -> u64 {
    if data_len == 0 {
        return 0;
    }
    let data = slice::from_raw_parts(data_ptr, data_len);
    let password = slice::from_raw_parts(key_ptr, key_len);
    let nonce = slice::from_raw_parts(nonce_ptr, 12);

    let output_len = 12 + data_len;
    let out_ptr = alloc_inline(output_len);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, output_len);

    output[..12].copy_from_slice(nonce);

    let mut key = [0u8; 32];
    derive_key(password, nonce, &mut key);

    let mut round_keys = [0u8; 240];
    aes_key_expansion(&key, &mut round_keys);

    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce);

    let mut keystream = [0u8; 16];
    let mut pos = 0usize;
    while pos < data_len {
        aes_encrypt_block(&counter, &mut keystream, &round_keys);

        let mut i = 0usize;
        while i < 16 && pos + i < data_len {
            output[12 + pos + i] = data[pos + i] ^ keystream[i];
            i += 1;
        }
        pos += 16;

        let mut j = 15isize;
        while j >= 12 {
            counter[j as usize] = counter[j as usize].wrapping_add(1);
            if counter[j as usize] != 0 {
                break;
            }
            j -= 1;
        }
    }

    pack(out_ptr, output_len)
}

#[no_mangle]
pub unsafe extern "C" fn aes_ctr_decrypt(
    data_ptr: *const u8,
    data_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> u64 {
    if data_len <= 12 {
        return 0;
    }
    let data = slice::from_raw_parts(data_ptr, data_len);
    let password = slice::from_raw_parts(key_ptr, key_len);
    let nonce_slice = &data[..12];
    let ciphertext = &data[12..];

    let output_len = ciphertext.len();
    let out_ptr = alloc_inline(output_len);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, output_len);

    let mut key = [0u8; 32];
    derive_key(password, nonce_slice, &mut key);

    let mut round_keys = [0u8; 240];
    aes_key_expansion(&key, &mut round_keys);

    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce_slice);

    let mut keystream = [0u8; 16];
    let mut pos = 0usize;
    while pos < output_len {
        aes_encrypt_block(&counter, &mut keystream, &round_keys);
        let mut i = 0usize;
        while i < 16 && pos + i < output_len {
            output[pos + i] = ciphertext[pos + i] ^ keystream[i];
            i += 1;
        }
        pos += 16;

        let mut j = 15isize;
        while j >= 12 {
            counter[j as usize] = counter[j as usize].wrapping_add(1);
            if counter[j as usize] != 0 {
                break;
            }
            j -= 1;
        }
    }

    pack(out_ptr, output_len)
}

#[no_mangle]
pub unsafe extern "C" fn generate_nonce(seed_ptr: *const u8, seed_len: usize) -> u64 {
    let out_ptr = alloc_inline(12);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, 12);

    let mut state: u64 = 0x853c49e6748fea9b;
    let seed = slice::from_raw_parts(seed_ptr, seed_len);
    for &b in seed {
        state ^= b as u64;
        state = state.wrapping_mul(0x2545F4914F6CDD1D);
    }

    for i in 0..12 {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        output[i] = (state.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8;
    }

    pack(out_ptr, 12)
}

// ============================================================================
// QR CODE GENERATION
// ============================================================================

const QR_MAX_VERSION: usize = 10;

const QR_CAPACITY: [usize; 11] = [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271];
const QR_EC_CODEWORDS: [usize; 11] = [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18];
const QR_NUM_BLOCKS: [usize; 11] = [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4];

static mut QR_MODULES: [u8; 60 * 60] = [0u8; 60 * 60];
static mut QR_SIZE: usize = 0;

#[inline]
fn qr_dim(version: usize) -> usize {
    17 + version * 4
}

unsafe fn set_module(x: usize, y: usize, value: u8) {
    if x < QR_SIZE && y < QR_SIZE {
        QR_MODULES[y * QR_SIZE + x] = value;
    }
}

unsafe fn get_module(x: usize, y: usize) -> u8 {
    if x < QR_SIZE && y < QR_SIZE {
        QR_MODULES[y * QR_SIZE + x]
    } else {
        0
    }
}

unsafe fn draw_finder(cx: usize, cy: usize) {
    let mut dy: i32 = -3;
    while dy <= 3 {
        let mut dx: i32 = -3;
        while dx <= 3 {
            let x = (cx as i32 + dx) as usize;
            let y = (cy as i32 + dy) as usize;
            let dist = dx.abs().max(dy.abs());
            set_module(x, y, if dist != 2 { 1 } else { 0 });
            dx += 1;
        }
        dy += 1;
    }
}

unsafe fn draw_alignment(cx: usize, cy: usize) {
    let mut dy: i32 = -2;
    while dy <= 2 {
        let mut dx: i32 = -2;
        while dx <= 2 {
            let x = (cx as i32 + dx) as usize;
            let y = (cy as i32 + dy) as usize;
            let dist = dx.abs().max(dy.abs());
            set_module(x, y, if dist != 1 { 1 } else { 0 });
            dx += 1;
        }
        dy += 1;
    }
}

const ALIGNMENT_POS: [&[usize]; 11] = [
    &[],
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
];

unsafe fn draw_function_patterns(version: usize) {
    draw_finder(3, 3);
    draw_finder(QR_SIZE - 4, 3);
    draw_finder(3, QR_SIZE - 4);

    let mut i = 8usize;
    while i < QR_SIZE - 8 {
        let v: u8 = ((i & 1) ^ 1) as u8;
        set_module(i, 6, v);
        set_module(6, i, v);
        i += 1;
    }

    if version >= 2 {
        let positions = ALIGNMENT_POS[version];
        for &py in positions {
            for &px in positions {
                if px <= 8 && py <= 8 {
                    continue;
                }
                if px >= QR_SIZE - 8 && py <= 8 {
                    continue;
                }
                if px <= 8 && py >= QR_SIZE - 8 {
                    continue;
                }
                draw_alignment(px, py);
            }
        }
    }

    set_module(8, QR_SIZE - 8, 1);
}

unsafe fn reserve_format_areas() {
    for i in 0..9 {
        set_module(i, 8, 2);
        set_module(8, i, 2);
    }
    for i in (QR_SIZE - 8)..QR_SIZE {
        set_module(i, 8, 2);
    }
    for i in (QR_SIZE - 7)..QR_SIZE {
        set_module(8, i, 2);
    }
}

unsafe fn is_data_area(x: usize, y: usize) -> bool {
    if x == 6 || y == 6 {
        return false;
    }
    if x <= 8 && y <= 8 {
        return false;
    }
    if x >= QR_SIZE - 8 && y <= 8 {
        return false;
    }
    if x <= 8 && y >= QR_SIZE - 8 {
        return false;
    }
    if get_module(x, y) == 2 {
        return false;
    }
    true
}

const GF_EXP: [u8; 512] = {
    let mut exp = [0u8; 512];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 256 {
        exp[i] = x as u8;
        x <<= 1;
        if x >= 256 {
            x ^= 0x11D;
        }
        i += 1;
    }
    let mut i = 256;
    while i < 512 {
        exp[i] = exp[i - 256];
        i += 1;
    }
    exp
};

const GF_LOG: [u8; 256] = {
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0u16;
    while i < 255 {
        log[(x as u8) as usize] = i as u8;
        x <<= 1;
        if x >= 256 {
            x ^= 0x11D;
        }
        i += 1;
    }
    log
};

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    GF_EXP[GF_LOG[a as usize] as usize + GF_LOG[b as usize] as usize]
}

fn rs_encode(data: &[u8], ec_len: usize, ec_out: &mut [u8]) {
    let mut gen = [0u8; 32];
    gen[0] = 1;
    let mut gen_len = 1usize;

    for i in 0..ec_len {
        let mut new_gen = [0u8; 32];
        let factor = GF_EXP[i];
        for j in 0..gen_len {
            new_gen[j + 1] ^= gen[j];
            new_gen[j] ^= gf_mul(gen[j], factor);
        }
        gen_len += 1;
        gen[..gen_len].copy_from_slice(&new_gen[..gen_len]);
    }

    let mut remainder = [0u8; 32];
    for &b in data {
        let factor = remainder[0] ^ b;
        for j in 0..ec_len - 1 {
            remainder[j] = remainder[j + 1];
        }
        remainder[ec_len - 1] = 0;
        for j in 0..ec_len {
            remainder[j] ^= gf_mul(gen[ec_len - 1 - j], factor);
        }
    }

    ec_out[..ec_len].copy_from_slice(&remainder[..ec_len]);
}

unsafe fn place_data(data: &[u8], data_bits: usize) {
    let mut bit_idx = 0usize;
    let mut x = QR_SIZE - 1;
    let mut going_up = true;

    loop {
        if x == 6 {
            x -= 1;
        }

        let mut y: isize = if going_up {
            (QR_SIZE - 1) as isize
        } else {
            0
        };

        loop {
            for i in 0..2 {
                let col = x - i;
                if is_data_area(col, y as usize) && get_module(col, y as usize) != 2 {
                    let bit: u8 = if bit_idx < data_bits {
                        ((data[bit_idx / 8] >> (7 - (bit_idx % 8) as u8)) & 1) as u8
                    } else {
                        0
                    };
                    set_module(col, y as usize, bit);
                    bit_idx += 1;
                }
            }

            if going_up {
                if y == 0 {
                    break;
                }
                y -= 1;
            } else {
                y += 1;
                if y as usize >= QR_SIZE {
                    break;
                }
            }
        }

        going_up = !going_up;
        if x < 2 {
            break;
        }
        x -= 2;
    }
}

unsafe fn apply_mask() {
    for y in 0..QR_SIZE {
        for x in 0..QR_SIZE {
            if is_data_area(x, y) && (x + y) % 2 == 0 {
                let v = get_module(x, y);
                set_module(x, y, v ^ 1);
            }
        }
    }
}

unsafe fn write_format_info() {
    let format_bits: u16 = 0x77C4;

    for i in 0..6 {
        let bit: u8 = ((format_bits >> i) & 1) as u8;
        set_module(i, 8, bit);
    }
    set_module(7, 8, ((format_bits >> 6) & 1) as u8);
    set_module(8, 8, ((format_bits >> 7) & 1) as u8);
    set_module(8, 7, ((format_bits >> 8) & 1) as u8);
    for i in 0..6 {
        let bit: u8 = ((format_bits >> (9 + i)) & 1) as u8;
        set_module(8, 5 - i, bit);
    }

    for i in 0..7 {
        let bit: u8 = ((format_bits >> i) & 1) as u8;
        set_module(8, QR_SIZE - 1 - i, bit);
    }
    for i in 0..8 {
        let bit: u8 = ((format_bits >> (7 + i)) & 1) as u8;
        set_module(QR_SIZE - 8 + i, 8, bit);
    }
}

#[no_mangle]
pub unsafe extern "C" fn generate_qr(data_ptr: *const u8, data_len: usize) -> u64 {
    if data_len == 0 {
        return 0;
    }
    let data = slice::from_raw_parts(data_ptr, data_len);

    let mut version = 1usize;
    while version <= QR_MAX_VERSION {
        if QR_CAPACITY[version] >= data_len + 3 {
            break;
        }
        version += 1;
    }
    if version > QR_MAX_VERSION {
        return 0;
    }

    QR_SIZE = qr_dim(version);

    let mods = &raw mut QR_MODULES;
    for i in 0..(60 * 60) {
        (*mods)[i] = 0;
    }

    draw_function_patterns(version);
    reserve_format_areas();

    let total_codewords = QR_CAPACITY[version] + QR_EC_CODEWORDS[version] * QR_NUM_BLOCKS[version];
    let data_codewords = QR_CAPACITY[version];
    let ec_per_block = QR_EC_CODEWORDS[version];

    let mut codewords = [0u8; 300];
    let mut cw_idx;

    if version < 10 {
        codewords[0] = 0x40 | ((data_len >> 4) as u8);
        codewords[1] = (data_len << 4) as u8;
        cw_idx = 1usize;
        let bit_offset: u8 = 4;
        for &b in data {
            codewords[cw_idx] |= b >> bit_offset;
            cw_idx += 1;
            codewords[cw_idx] = ((b as u16) << (8 - bit_offset as u16)) as u8;
        }
        cw_idx += 1;
    } else {
        codewords[0] = 0x40;
        codewords[1] = (data_len >> 8) as u8;
        codewords[2] = data_len as u8;
        for (i, &b) in data.iter().enumerate() {
            codewords[3 + i] = b;
        }
        cw_idx = 3 + data_len;
    }

    while cw_idx < data_codewords {
        codewords[cw_idx] = if cw_idx % 2 == 0 { 0xEC } else { 0x11 };
        cw_idx += 1;
    }

    let mut ec_data = [0u8; 300];
    let blocks = QR_NUM_BLOCKS[version];
    let block_size = data_codewords / blocks;

    for b in 0..blocks {
        let src = &codewords[b * block_size..(b + 1) * block_size];
        let dst = &mut ec_data[b * ec_per_block..(b + 1) * ec_per_block];
        rs_encode(src, ec_per_block, dst);
    }

    let mut final_data = [0u8; 400];
    let mut final_idx = 0usize;

    for i in 0..block_size {
        for b in 0..blocks {
            final_data[final_idx] = codewords[b * block_size + i];
            final_idx += 1;
        }
    }
    for i in 0..ec_per_block {
        for b in 0..blocks {
            final_data[final_idx] = ec_data[b * ec_per_block + i];
            final_idx += 1;
        }
    }

    place_data(&final_data, total_codewords * 8);
    apply_mask();
    write_format_info();

    let output_size = QR_SIZE * QR_SIZE;
    let out_ptr = alloc_inline(output_size);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, output_size);

    for y in 0..QR_SIZE {
        for x in 0..QR_SIZE {
            output[y * QR_SIZE + x] = get_module(x, y) & 1;
        }
    }

    ((out_ptr as usize as u64) << 32) | ((QR_SIZE as u64) << 16) | (output_size as u64)
}

#[no_mangle]
pub unsafe extern "C" fn get_qr_size(result: u64) -> usize {
    ((result >> 16) & 0xFFFF) as usize
}

// ============================================================================
// HASH (xxHash-inspired) -> 11-char base64url
// ============================================================================

const PRIME1: u64 = 0x9E3779B185EBCA87;
const PRIME2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME3: u64 = 0x165667B19E3779F9;
const PRIME5: u64 = 0x27D4EB2F165667C5;

#[inline]
fn xxh_round(acc: u64, input: u64) -> u64 {
    let mut a = acc.wrapping_add(input.wrapping_mul(PRIME2));
    a = (a << 31) | (a >> 33);
    a.wrapping_mul(PRIME1)
}

#[inline]
fn xxh_avalanche(h: u64) -> u64 {
    let mut hash = h;
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME3);
    hash ^= hash >> 32;
    hash
}

#[no_mangle]
pub unsafe extern "C" fn hash_data(data_ptr: *const u8, data_len: usize) -> u64 {
    if data_len == 0 {
        return 0;
    }
    let data = slice::from_raw_parts(data_ptr, data_len);
    let mut h: u64 = PRIME5;

    let mut i = 0usize;
    while i + 8 <= data_len {
        let chunk = (data[i] as u64)
            | ((data[i + 1] as u64) << 8)
            | ((data[i + 2] as u64) << 16)
            | ((data[i + 3] as u64) << 24)
            | ((data[i + 4] as u64) << 32)
            | ((data[i + 5] as u64) << 40)
            | ((data[i + 6] as u64) << 48)
            | ((data[i + 7] as u64) << 56);
        h = xxh_round(h, chunk);
        i += 8;
    }

    while i < data_len {
        h ^= (data[i] as u64).wrapping_mul(PRIME5);
        h = ((h << 11) | (h >> 53)).wrapping_mul(PRIME1);
        i += 1;
    }

    h ^= data_len as u64;
    h = xxh_avalanche(h);

    let out_ptr = alloc_inline(11);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, 11);

    let mut remaining = h;
    for j in 0..11 {
        output[j] = BASE64URL_ALPHABET[(remaining & 0x3F) as usize];
        remaining >>= 6;
    }

    pack(out_ptr, 11)
}

// ============================================================================
// SESSION MANAGEMENT (12-hour expiry)
// ============================================================================

const SESSION_DURATION_SECS: u64 = 12 * 60 * 60;
const SESSION_ID_LEN: usize = 16;

static mut SESSION_ID: [u8; SESSION_ID_LEN] = [0u8; SESSION_ID_LEN];
static mut SESSION_CREATED_AT: u64 = 0;
static mut SESSION_ACTIVE: bool = false;
static mut PRNG_STATE: u64 = 0x853c49e6748fea9b;

unsafe fn prng_next() -> u64 {
    PRNG_STATE ^= PRNG_STATE >> 12;
    PRNG_STATE ^= PRNG_STATE << 25;
    PRNG_STATE ^= PRNG_STATE >> 27;
    PRNG_STATE.wrapping_mul(0x2545F4914F6CDD1D)
}

#[no_mangle]
pub unsafe extern "C" fn session_create(current_time_secs: u64, seed: u64) -> u64 {
    PRNG_STATE = current_time_secs ^ seed ^ 0x853c49e6748fea9b;
    for i in 0..SESSION_ID_LEN {
        let r = prng_next();
        SESSION_ID[i] = BASE64URL_ALPHABET[(r & 0x3F) as usize];
    }
    SESSION_CREATED_AT = current_time_secs;
    SESSION_ACTIVE = true;
    ((&raw const SESSION_ID as usize as u64) << 32) | (SESSION_ID_LEN as u64)
}

#[no_mangle]
pub unsafe extern "C" fn session_validate(current_time_secs: u64) -> u8 {
    if !SESSION_ACTIVE {
        return 0;
    }
    let elapsed = current_time_secs.saturating_sub(SESSION_CREATED_AT);
    if elapsed >= SESSION_DURATION_SECS {
        SESSION_ACTIVE = false;
        let sid = &raw mut SESSION_ID;
        for i in 0..SESSION_ID_LEN {
            (*sid)[i] = 0;
        }
        SESSION_CREATED_AT = 0;
        return 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn session_remaining(current_time_secs: u64) -> u64 {
    if !SESSION_ACTIVE {
        return 0;
    }
    let elapsed = current_time_secs.saturating_sub(SESSION_CREATED_AT);
    if elapsed >= SESSION_DURATION_SECS {
        return 0;
    }
    SESSION_DURATION_SECS - elapsed
}

#[no_mangle]
pub unsafe extern "C" fn session_get_id() -> u64 {
    if !SESSION_ACTIVE {
        return 0;
    }
    ((&raw const SESSION_ID as usize as u64) << 32) | (SESSION_ID_LEN as u64)
}

#[no_mangle]
pub unsafe extern "C" fn session_invalidate() {
    SESSION_ACTIVE = false;
    let sid = &raw mut SESSION_ID;
    for i in 0..SESSION_ID_LEN {
        (*sid)[i] = 0;
    }
    SESSION_CREATED_AT = 0;
}

#[no_mangle]
pub unsafe extern "C" fn session_refresh(current_time_secs: u64) -> u8 {
    if !SESSION_ACTIVE {
        return 0;
    }
    let elapsed = current_time_secs.saturating_sub(SESSION_CREATED_AT);
    if elapsed >= SESSION_DURATION_SECS {
        SESSION_ACTIVE = false;
        let sid = &raw mut SESSION_ID;
        for i in 0..SESSION_ID_LEN {
            (*sid)[i] = 0;
        }
        SESSION_CREATED_AT = 0;
        return 0;
    }
    SESSION_CREATED_AT = current_time_secs;
    1
}

#[no_mangle]
pub unsafe extern "C" fn session_is_active() -> u8 {
    if SESSION_ACTIVE {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn session_get_created_at() -> u64 {
    SESSION_CREATED_AT
}

// ============================================================================
// SYNTAX HIGHLIGHTING LEXER
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy)]
enum TokenType {
    Keyword = 1,
    StringLit = 2,
    Number = 3,
    Comment = 4,
    Operator = 5,
    Punctuation = 6,
    FunctionName = 7,
    TypeName = 8,
    #[allow(dead_code)]
    Variable = 9,
    Tag = 10,
    Attribute = 11,
    Property = 12,
}

const TOKEN_SIZE: usize = 9;
const MAX_TOKENS: usize = 50_000;

const JS_KEYWORDS: &[&str] = &[
    "async", "await", "break", "case", "catch", "class", "const", "continue",
    "debugger", "default", "delete", "do", "else", "export", "extends", "false",
    "finally", "for", "from", "function", "if", "import", "in", "instanceof",
    "let", "new", "null", "of", "return", "static", "super", "switch", "this",
    "throw", "true", "try", "typeof", "undefined", "var", "void", "while", "with", "yield",
];

const PYTHON_KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break",
    "class", "continue", "def", "del", "elif", "else", "except", "finally",
    "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

const ZIG_KEYWORDS: &[&str] = &[
    "addrspace", "align", "allowzero", "and", "anyframe", "anytype", "asm",
    "async", "await", "break", "callconv", "catch", "comptime", "const",
    "continue", "defer", "else", "enum", "errdefer", "error", "export",
    "extern", "false", "fn", "for", "if", "inline", "noalias", "nosuspend",
    "null", "opaque", "or", "orelse", "packed", "pub", "resume", "return",
    "struct", "suspend", "switch", "test", "threadlocal", "true", "try",
    "undefined", "union", "unreachable", "usingnamespace", "var", "volatile", "while",
];

const CSS_KEYWORDS: &[&str] = &[
    "important", "inherit", "initial", "unset", "none", "auto", "block",
    "inline", "flex", "grid", "absolute", "relative", "fixed", "sticky",
    "hidden", "visible", "solid", "dashed", "dotted", "transparent",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    Plain = 0,
    Javascript = 1,
    Json = 2,
    Html = 3,
    Css = 4,
    Python = 5,
    Markdown = 6,
    Zig = 7,
}

fn lang_from_u8(v: u8) -> Language {
    match v {
        1 => Language::Javascript,
        2 => Language::Json,
        3 => Language::Html,
        4 => Language::Css,
        5 => Language::Python,
        6 => Language::Markdown,
        7 => Language::Zig,
        _ => Language::Plain,
    }
}

fn keywords_for(lang: Language) -> Option<&'static [&'static str]> {
    match lang {
        Language::Javascript | Language::Json => Some(JS_KEYWORDS),
        Language::Python => Some(PYTHON_KEYWORDS),
        Language::Zig => Some(ZIG_KEYWORDS),
        Language::Css => Some(CSS_KEYWORDS),
        _ => None,
    }
}

fn is_keyword(word: &[u8], lang: Language) -> bool {
    let Some(kws) = keywords_for(lang) else {
        return false;
    };
    for kw in kws {
        if word == kw.as_bytes() {
            return true;
        }
    }
    false
}

#[inline]
fn is_alpha(c: u8) -> bool {
    matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$')
}

#[inline]
fn is_alnum(c: u8) -> bool {
    is_alpha(c) || matches!(c, b'0'..=b'9')
}

#[inline]
fn is_digit(c: u8) -> bool {
    matches!(c, b'0'..=b'9')
}

#[inline]
fn is_hex_digit(c: u8) -> bool {
    is_digit(c) || matches!(c, b'a'..=b'f' | b'A'..=b'F')
}

#[inline]
fn is_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

fn write_token(output: &mut [u8], idx: &mut usize, start: usize, length: usize, t: TokenType) {
    if *idx + TOKEN_SIZE > output.len() {
        return;
    }
    let i = *idx;
    output[i] = start as u8;
    output[i + 1] = (start >> 8) as u8;
    output[i + 2] = (start >> 16) as u8;
    output[i + 3] = (start >> 24) as u8;
    output[i + 4] = length as u8;
    output[i + 5] = (length >> 8) as u8;
    output[i + 6] = (length >> 16) as u8;
    output[i + 7] = (length >> 24) as u8;
    output[i + 8] = t as u8;
    *idx += TOKEN_SIZE;
}

fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn tokenize_js(input: &[u8], output: &mut [u8]) -> usize {
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < input.len() && idx + TOKEN_SIZE <= output.len() {
        let c = input[pos];
        if is_whitespace(c) {
            pos += 1;
            continue;
        }
        if c == b'/' && pos + 1 < input.len() && input[pos + 1] == b'/' {
            let start = pos;
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Comment);
            continue;
        }
        if c == b'/' && pos + 1 < input.len() && input[pos + 1] == b'*' {
            let start = pos;
            pos += 2;
            while pos + 1 < input.len() && !(input[pos] == b'*' && input[pos + 1] == b'/') {
                pos += 1;
            }
            pos += 2;
            write_token(output, &mut idx, start, pos - start, TokenType::Comment);
            continue;
        }
        if c == b'"' || c == b'\'' || c == b'`' {
            let quote = c;
            let start = pos;
            pos += 1;
            while pos < input.len() {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else if input[pos] == quote {
                    pos += 1;
                    break;
                } else if quote != b'`' && input[pos] == b'\n' {
                    break;
                } else {
                    pos += 1;
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::StringLit);
            continue;
        }
        if is_digit(c) || (c == b'.' && pos + 1 < input.len() && is_digit(input[pos + 1])) {
            let start = pos;
            if c == b'0' && pos + 1 < input.len() && (input[pos + 1] == b'x' || input[pos + 1] == b'X') {
                pos += 2;
                while pos < input.len() && is_hex_digit(input[pos]) {
                    pos += 1;
                }
            } else {
                while pos < input.len() && (is_digit(input[pos]) || input[pos] == b'.') {
                    pos += 1;
                }
                if pos < input.len() && (input[pos] == b'e' || input[pos] == b'E') {
                    pos += 1;
                    if pos < input.len() && (input[pos] == b'+' || input[pos] == b'-') {
                        pos += 1;
                    }
                    while pos < input.len() && is_digit(input[pos]) {
                        pos += 1;
                    }
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Number);
            continue;
        }
        if is_alpha(c) {
            let start = pos;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            let word = &input[start..pos];
            if is_keyword(word, Language::Javascript) {
                write_token(output, &mut idx, start, pos - start, TokenType::Keyword);
            } else if pos < input.len() && input[pos] == b'(' {
                write_token(output, &mut idx, start, pos - start, TokenType::FunctionName);
            } else if !word.is_empty() && (word[0] >= b'A' && word[0] <= b'Z') {
                write_token(output, &mut idx, start, pos - start, TokenType::TypeName);
            }
            continue;
        }
        if matches!(
            c,
            b'+' | b'-' | b'*' | b'/' | b'=' | b'<' | b'>' | b'!' | b'&' | b'|' | b'^' | b'%' | b'~' | b'?'
        ) {
            let start = pos;
            pos += 1;
            if pos < input.len() {
                let next = input[pos];
                if (c == b'=' && (next == b'=' || next == b'>'))
                    || (c == b'!' && next == b'=')
                    || (c == b'<' && (next == b'=' || next == b'<'))
                    || (c == b'>' && (next == b'=' || next == b'>'))
                    || (c == b'&' && next == b'&')
                    || (c == b'|' && next == b'|')
                    || (c == b'+' && next == b'+')
                    || (c == b'-' && next == b'-')
                    || (c == b'*' && next == b'*')
                    || (c == b'?' && next == b'?')
                {
                    pos += 1;
                    if pos < input.len() && input[pos] == b'=' {
                        pos += 1;
                    }
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Operator);
            continue;
        }
        if matches!(c, b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b';' | b':' | b'.') {
            write_token(output, &mut idx, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
    idx
}

fn tokenize_html(input: &[u8], output: &mut [u8]) -> usize {
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < input.len() && idx + TOKEN_SIZE <= output.len() {
        let c = input[pos];
        if c == b'<' && pos + 3 < input.len() && input[pos + 1] == b'!' && input[pos + 2] == b'-' && input[pos + 3] == b'-' {
            let start = pos;
            pos += 4;
            while pos + 2 < input.len() && !(input[pos] == b'-' && input[pos + 1] == b'-' && input[pos + 2] == b'>') {
                pos += 1;
            }
            pos += 3;
            write_token(output, &mut idx, start, pos - start, TokenType::Comment);
            continue;
        }
        if c == b'<' {
            pos += 1;
            if pos < input.len() && input[pos] == b'/' {
                pos += 1;
            }
            let tag_start = pos;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            if pos > tag_start {
                write_token(output, &mut idx, tag_start, pos - tag_start, TokenType::Tag);
            }
            while pos < input.len() && input[pos] != b'>' {
                if is_whitespace(input[pos]) {
                    pos += 1;
                    continue;
                }
                if is_alpha(input[pos]) {
                    let attr_start = pos;
                    while pos < input.len() && (is_alnum(input[pos]) || input[pos] == b'-') {
                        pos += 1;
                    }
                    write_token(output, &mut idx, attr_start, pos - attr_start, TokenType::Attribute);
                    while pos < input.len() && is_whitespace(input[pos]) {
                        pos += 1;
                    }
                    if pos < input.len() && input[pos] == b'=' {
                        pos += 1;
                        while pos < input.len() && is_whitespace(input[pos]) {
                            pos += 1;
                        }
                        if pos < input.len() && (input[pos] == b'"' || input[pos] == b'\'') {
                            let quote = input[pos];
                            let val_start = pos;
                            pos += 1;
                            while pos < input.len() && input[pos] != quote {
                                pos += 1;
                            }
                            pos += 1;
                            write_token(output, &mut idx, val_start, pos - val_start, TokenType::StringLit);
                        }
                    }
                    continue;
                }
                pos += 1;
            }
            if pos < input.len() {
                pos += 1;
            }
            continue;
        }
        pos += 1;
    }
    idx
}

fn tokenize_css(input: &[u8], output: &mut [u8]) -> usize {
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < input.len() && idx + TOKEN_SIZE <= output.len() {
        let c = input[pos];
        if is_whitespace(c) {
            pos += 1;
            continue;
        }
        if c == b'/' && pos + 1 < input.len() && input[pos + 1] == b'*' {
            let start = pos;
            pos += 2;
            while pos + 1 < input.len() && !(input[pos] == b'*' && input[pos + 1] == b'/') {
                pos += 1;
            }
            pos += 2;
            write_token(output, &mut idx, start, pos - start, TokenType::Comment);
            continue;
        }
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = pos;
            pos += 1;
            while pos < input.len() && input[pos] != quote {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            if pos < input.len() {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::StringLit);
            continue;
        }
        if is_digit(c) || (c == b'.' && pos + 1 < input.len() && is_digit(input[pos + 1])) {
            let start = pos;
            while pos < input.len() && (is_digit(input[pos]) || input[pos] == b'.') {
                pos += 1;
            }
            while pos < input.len() && is_alpha(input[pos]) {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Number);
            continue;
        }
        if c == b'#' {
            let start = pos;
            pos += 1;
            while pos < input.len() && is_hex_digit(input[pos]) {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Number);
            continue;
        }
        if is_alpha(c) || c == b'-' || c == b'_' {
            let start = pos;
            while pos < input.len() && (is_alnum(input[pos]) || input[pos] == b'-' || input[pos] == b'_') {
                pos += 1;
            }
            let word = &input[start..pos];
            if is_keyword(word, Language::Css) {
                write_token(output, &mut idx, start, pos - start, TokenType::Keyword);
            } else {
                write_token(output, &mut idx, start, pos - start, TokenType::Property);
            }
            continue;
        }
        if matches!(c, b'{' | b'}' | b':' | b';' | b',' | b'(' | b')') {
            write_token(output, &mut idx, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
    idx
}

fn tokenize_python(input: &[u8], output: &mut [u8]) -> usize {
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < input.len() && idx + TOKEN_SIZE <= output.len() {
        let c = input[pos];
        if is_whitespace(c) {
            pos += 1;
            continue;
        }
        if c == b'#' {
            let start = pos;
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Comment);
            continue;
        }
        if (c == b'"' || c == b'\'') && pos + 2 < input.len() && input[pos + 1] == c && input[pos + 2] == c {
            let quote = c;
            let start = pos;
            pos += 3;
            while pos + 2 < input.len() && !(input[pos] == quote && input[pos + 1] == quote && input[pos + 2] == quote) {
                pos += 1;
            }
            pos += 3;
            write_token(output, &mut idx, start, pos - start, TokenType::StringLit);
            continue;
        }
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = pos;
            pos += 1;
            while pos < input.len() && input[pos] != quote && input[pos] != b'\n' {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            if pos < input.len() && input[pos] == quote {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::StringLit);
            continue;
        }
        if is_digit(c) {
            let start = pos;
            if c == b'0' && pos + 1 < input.len() {
                let next = input[pos + 1];
                if matches!(next, b'x' | b'X' | b'b' | b'B' | b'o' | b'O') {
                    pos += 2;
                    while pos < input.len() && (is_hex_digit(input[pos]) || input[pos] == b'_') {
                        pos += 1;
                    }
                    write_token(output, &mut idx, start, pos - start, TokenType::Number);
                    continue;
                }
            }
            while pos < input.len() && (is_digit(input[pos]) || input[pos] == b'.' || input[pos] == b'_') {
                pos += 1;
            }
            if pos < input.len() && (input[pos] == b'e' || input[pos] == b'E') {
                pos += 1;
                if pos < input.len() && (input[pos] == b'+' || input[pos] == b'-') {
                    pos += 1;
                }
                while pos < input.len() && is_digit(input[pos]) {
                    pos += 1;
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Number);
            continue;
        }
        if is_alpha(c) {
            let start = pos;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            let word = &input[start..pos];
            if is_keyword(word, Language::Python) {
                write_token(output, &mut idx, start, pos - start, TokenType::Keyword);
            } else if pos < input.len() && input[pos] == b'(' {
                write_token(output, &mut idx, start, pos - start, TokenType::FunctionName);
            } else if !word.is_empty() && (word[0] >= b'A' && word[0] <= b'Z') {
                write_token(output, &mut idx, start, pos - start, TokenType::TypeName);
            }
            continue;
        }
        if matches!(
            c,
            b'+' | b'-' | b'*' | b'/' | b'=' | b'<' | b'>' | b'!' | b'&' | b'|' | b'^' | b'%' | b'~' | b'@'
        ) {
            let start = pos;
            pos += 1;
            if pos < input.len() && (input[pos] == b'=' || input[pos] == c) {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Operator);
            continue;
        }
        if matches!(c, b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b':' | b'.') {
            write_token(output, &mut idx, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
    idx
}

fn tokenize_json(input: &[u8], output: &mut [u8]) -> usize {
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < input.len() && idx + TOKEN_SIZE <= output.len() {
        let c = input[pos];
        if is_whitespace(c) {
            pos += 1;
            continue;
        }
        if c == b'"' {
            let start = pos;
            pos += 1;
            while pos < input.len() && input[pos] != b'"' {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            if pos < input.len() {
                pos += 1;
            }
            let mut peek = pos;
            while peek < input.len() && is_whitespace(input[peek]) {
                peek += 1;
            }
            if peek < input.len() && input[peek] == b':' {
                write_token(output, &mut idx, start, pos - start, TokenType::Property);
            } else {
                write_token(output, &mut idx, start, pos - start, TokenType::StringLit);
            }
            continue;
        }
        if is_digit(c) || c == b'-' {
            let start = pos;
            if c == b'-' {
                pos += 1;
            }
            while pos < input.len() && is_digit(input[pos]) {
                pos += 1;
            }
            if pos < input.len() && input[pos] == b'.' {
                pos += 1;
                while pos < input.len() && is_digit(input[pos]) {
                    pos += 1;
                }
            }
            if pos < input.len() && (input[pos] == b'e' || input[pos] == b'E') {
                pos += 1;
                if pos < input.len() && (input[pos] == b'+' || input[pos] == b'-') {
                    pos += 1;
                }
                while pos < input.len() && is_digit(input[pos]) {
                    pos += 1;
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Number);
            continue;
        }
        if is_alpha(c) {
            let start = pos;
            while pos < input.len() && is_alpha(input[pos]) {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Keyword);
            continue;
        }
        if matches!(c, b'{' | b'}' | b'[' | b']' | b':' | b',') {
            write_token(output, &mut idx, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
    idx
}

fn tokenize_zig(input: &[u8], output: &mut [u8]) -> usize {
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < input.len() && idx + TOKEN_SIZE <= output.len() {
        let c = input[pos];
        if is_whitespace(c) {
            pos += 1;
            continue;
        }
        if c == b'/' && pos + 1 < input.len() && input[pos + 1] == b'/' {
            let start = pos;
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Comment);
            continue;
        }
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = pos;
            pos += 1;
            while pos < input.len() {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else if input[pos] == quote {
                    pos += 1;
                    break;
                } else if input[pos] == b'\n' {
                    break;
                } else {
                    pos += 1;
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::StringLit);
            continue;
        }
        if is_digit(c) || (c == b'.' && pos + 1 < input.len() && is_digit(input[pos + 1])) {
            let start = pos;
            if c == b'0' && pos + 1 < input.len() && matches!(input[pos + 1], b'x' | b'b' | b'o') {
                pos += 2;
                while pos < input.len() && (is_hex_digit(input[pos]) || input[pos] == b'_') {
                    pos += 1;
                }
            } else {
                while pos < input.len() && (is_digit(input[pos]) || input[pos] == b'.' || input[pos] == b'_') {
                    pos += 1;
                }
                if pos < input.len() && (input[pos] == b'e' || input[pos] == b'E') {
                    pos += 1;
                    if pos < input.len() && (input[pos] == b'+' || input[pos] == b'-') {
                        pos += 1;
                    }
                    while pos < input.len() && is_digit(input[pos]) {
                        pos += 1;
                    }
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Number);
            continue;
        }
        if c == b'@' && pos + 1 < input.len() && is_alpha(input[pos + 1]) {
            let start = pos;
            pos += 1;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::FunctionName);
            continue;
        }
        if is_alpha(c) {
            let start = pos;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            let word = &input[start..pos];
            if is_keyword(word, Language::Zig) {
                write_token(output, &mut idx, start, pos - start, TokenType::Keyword);
            } else if pos < input.len() && input[pos] == b'(' {
                write_token(output, &mut idx, start, pos - start, TokenType::FunctionName);
            } else if !word.is_empty() && (word[0] >= b'A' && word[0] <= b'Z') {
                write_token(output, &mut idx, start, pos - start, TokenType::TypeName);
            }
            continue;
        }
        if matches!(
            c,
            b'+' | b'-' | b'*' | b'/' | b'=' | b'<' | b'>' | b'!' | b'&' | b'|' | b'^' | b'%' | b'~' | b'?'
        ) {
            let start = pos;
            pos += 1;
            if pos < input.len() {
                let next = input[pos];
                if (c == b'=' && next == b'=')
                    || (c == b'!' && next == b'=')
                    || (c == b'<' && (next == b'=' || next == b'<'))
                    || (c == b'>' && (next == b'=' || next == b'>'))
                    || (c == b'+' && next == b'+')
                    || (c == b'*' && next == b'*')
                {
                    pos += 1;
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Operator);
            continue;
        }
        if matches!(c, b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b';' | b':' | b'.') {
            write_token(output, &mut idx, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
    idx
}

fn tokenize_markdown(input: &[u8], output: &mut [u8]) -> usize {
    let mut idx = 0usize;
    let mut pos = 0usize;
    while pos < input.len() && idx + TOKEN_SIZE <= output.len() {
        let c = input[pos];
        if c == b'#' && (pos == 0 || input[pos - 1] == b'\n') {
            let start = pos;
            while pos < input.len() && input[pos] == b'#' {
                pos += 1;
            }
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Keyword);
            continue;
        }
        if c == b'`' && pos + 2 < input.len() && input[pos + 1] == b'`' && input[pos + 2] == b'`' {
            let start = pos;
            pos += 3;
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            while pos + 2 < input.len() {
                if input[pos] == b'`' && input[pos + 1] == b'`' && input[pos + 2] == b'`' {
                    pos += 3;
                    break;
                }
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Comment);
            continue;
        }
        if c == b'`' {
            let start = pos;
            pos += 1;
            while pos < input.len() && input[pos] != b'`' && input[pos] != b'\n' {
                pos += 1;
            }
            if pos < input.len() && input[pos] == b'`' {
                pos += 1;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::StringLit);
            continue;
        }
        if c == b'*' && pos + 1 < input.len() && input[pos + 1] == b'*' {
            let start = pos;
            pos += 2;
            while pos + 1 < input.len() && !(input[pos] == b'*' && input[pos + 1] == b'*') {
                pos += 1;
            }
            if pos + 1 < input.len() {
                pos += 2;
            }
            write_token(output, &mut idx, start, pos - start, TokenType::TypeName);
            continue;
        }
        if c == b'[' {
            let start = pos;
            pos += 1;
            while pos < input.len() && input[pos] != b']' && input[pos] != b'\n' {
                pos += 1;
            }
            if pos < input.len() && input[pos] == b']' {
                pos += 1;
                if pos < input.len() && input[pos] == b'(' {
                    pos += 1;
                    while pos < input.len() && input[pos] != b')' && input[pos] != b'\n' {
                        pos += 1;
                    }
                    if pos < input.len() && input[pos] == b')' {
                        pos += 1;
                    }
                }
            }
            write_token(output, &mut idx, start, pos - start, TokenType::Tag);
            continue;
        }
        pos += 1;
    }
    idx
}

#[no_mangle]
pub unsafe extern "C" fn tokenize(input_ptr: *const u8, input_len: usize, lang: u8) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let max_output = MAX_TOKENS * TOKEN_SIZE;
    let out_ptr = alloc_inline(max_output);
    if out_ptr.is_null() {
        return 0;
    }
    let output = slice::from_raw_parts_mut(out_ptr, max_output);

    let language = lang_from_u8(lang);
    let bytes_written = match language {
        Language::Javascript => tokenize_js(input, output),
        Language::Json => tokenize_json(input, output),
        Language::Html => tokenize_html(input, output),
        Language::Css => tokenize_css(input, output),
        Language::Python => tokenize_python(input, output),
        Language::Zig => tokenize_zig(input, output),
        Language::Markdown => tokenize_markdown(input, output),
        _ => 0,
    };

    pack(out_ptr, bytes_written)
}

#[no_mangle]
pub unsafe extern "C" fn detect_language(input_ptr: *const u8, input_len: usize) -> u8 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);

    let mut i = 0usize;
    while i < input_len && is_whitespace(input[i]) {
        i += 1;
    }
    if i + 1 < input_len && input[i] == b'<' && (input[i + 1] == b'!' || is_alpha(input[i + 1])) {
        return Language::Html as u8;
    }
    if i < input_len && (input[i] == b'{' || input[i] == b'[') {
        return Language::Json as u8;
    }

    if input_len > 2 && input[0] == b'#' && input[1] == b'!' {
        let head = &input[..input_len.min(50)];
        if memmem(head, b"python").is_some() {
            return Language::Python as u8;
        }
    }

    let head = &input[..input_len.min(500)];
    if memmem(head, b"def ").is_some() {
        return Language::Python as u8;
    }
    if memmem(head, b"import ").is_some() && memmem(head, b"from ").is_some() {
        return Language::Python as u8;
    }

    if memmem(head, b"{").is_some()
        && (memmem(head, b"color:").is_some()
            || memmem(head, b"margin:").is_some()
            || memmem(head, b"padding:").is_some())
    {
        return Language::Css as u8;
    }

    if memmem(head, b"function").is_some()
        || memmem(head, b"const ").is_some()
        || memmem(head, b"let ").is_some()
        || memmem(head, b"var ").is_some()
    {
        return Language::Javascript as u8;
    }

    Language::Plain as u8
}
