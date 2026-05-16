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
// BUMP HEAP
// ============================================================================

const HEAP_SIZE: usize = 4 * 1024 * 1024;

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
pub unsafe extern "C" fn reset_heap() {
    HEAP_OFFSET = 0;
}

#[inline]
fn pack(p: *const u8, len: usize) -> u64 {
    ((p as usize as u64) << 32) | (len as u64)
}

// ============================================================================
// BASE64URL
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
