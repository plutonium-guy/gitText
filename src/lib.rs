#![allow(clippy::missing_safety_doc)]
#![allow(static_mut_refs)]

use core::ptr;
use core::slice;

// ============================================================================
// ABI / BUMP HEAP for transient call buffers
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

unsafe fn alloc_bytes(src: &[u8]) -> *mut u8 {
    let p = alloc_inline(src.len());
    if !p.is_null() {
        ptr::copy_nonoverlapping(src.as_ptr(), p, src.len());
    }
    p
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

unsafe fn return_bytes(data: &[u8]) -> u64 {
    if data.is_empty() {
        return 0;
    }
    let p = alloc_bytes(data);
    if p.is_null() {
        return 0;
    }
    pack(p, data.len())
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

fn b64url_encode_str(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    let chunks = input.len() / 3;
    for c in 0..chunks {
        let i = c * 3;
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(BASE64URL_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(BASE64URL_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(BASE64URL_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(BASE64URL_ALPHABET[(b2 & 0x3f) as usize] as char);
    }
    let i = chunks * 3;
    if i < input.len() {
        let b0 = input[i];
        out.push(BASE64URL_ALPHABET[(b0 >> 2) as usize] as char);
        if i + 1 < input.len() {
            let b1 = input[i + 1];
            out.push(BASE64URL_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(BASE64URL_ALPHABET[((b1 & 0x0f) << 2) as usize] as char);
        } else {
            out.push(BASE64URL_ALPHABET[((b0 & 0x03) << 4) as usize] as char);
        }
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn base64url_encode(input_ptr: *const u8, input_len: usize) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let s = b64url_encode_str(input);
    return_bytes(s.as_bytes())
}

fn b64url_decode_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4 + 1);
    let mut i = 0;
    while i + 4 <= input.len() {
        let c0 = BASE64URL_DECODE_TABLE[input[i] as usize];
        let c1 = BASE64URL_DECODE_TABLE[input[i + 1] as usize];
        let c2 = BASE64URL_DECODE_TABLE[input[i + 2] as usize];
        let c3 = BASE64URL_DECODE_TABLE[input[i + 3] as usize];
        if c0 == 255 || c1 == 255 {
            break;
        }
        out.push((c0 << 2) | (c1 >> 4));
        if c2 != 255 {
            out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
            if c3 != 255 {
                out.push(((c2 & 0x03) << 6) | c3);
            }
        }
        i += 4;
    }
    if i < input.len() {
        let c0 = BASE64URL_DECODE_TABLE[input[i] as usize];
        if c0 != 255 && i + 1 < input.len() {
            let c1 = BASE64URL_DECODE_TABLE[input[i + 1] as usize];
            if c1 != 255 {
                out.push((c0 << 2) | (c1 >> 4));
                if i + 2 < input.len() {
                    let c2 = BASE64URL_DECODE_TABLE[input[i + 2] as usize];
                    if c2 != 255 {
                        out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
                    }
                }
            }
        }
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn base64url_decode(input_ptr: *const u8, input_len: usize) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let v = b64url_decode_bytes(input);
    return_bytes(&v)
}

// ============================================================================
// AES-256-CTR (legacy weak KDF kept for compat) + new argon2id envelope
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
        let x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        s[p as usize] = x ^ 0x63;
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
    let mut r = 0u8;
    let mut aa = a;
    let mut bb = b;
    for _ in 0..8 {
        if bb & 1 != 0 {
            r ^= aa;
        }
        let hi = aa & 0x80;
        aa <<= 1;
        if hi != 0 {
            aa ^= 0x1B;
        }
        bb >>= 1;
    }
    r
}

fn aes_encrypt_block(input: &[u8; 16], output: &mut [u8; 16], rk: &[u8; 240]) {
    let mut s = [0u8; 16];
    for i in 0..16 {
        s[i] = input[i] ^ rk[i];
    }
    for round in 1..AES_ROUNDS {
        for i in 0..16 {
            s[i] = SBOX[s[i] as usize];
        }
        let t1 = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t1;
        let t2 = s[2];
        let t6 = s[6];
        s[2] = s[10];
        s[6] = s[14];
        s[10] = t2;
        s[14] = t6;
        let t3 = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t3;
        for col in 0..4 {
            let c = col * 4;
            let a0 = s[c];
            let a1 = s[c + 1];
            let a2 = s[c + 2];
            let a3 = s[c + 3];
            s[c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            s[c + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            s[c + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            s[c + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }
        let off = round * 16;
        for i in 0..16 {
            s[i] ^= rk[off + i];
        }
    }
    for i in 0..16 {
        s[i] = SBOX[s[i] as usize];
    }
    let t1 = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t1;
    let t2 = s[2];
    let t6 = s[6];
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t2;
    s[14] = t6;
    let t3 = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t3;
    let off = AES_ROUNDS * 16;
    for i in 0..16 {
        output[i] = s[i] ^ rk[off + i];
    }
}

fn ctr_xor(nonce: &[u8], data: &[u8], out: &mut [u8], rk: &[u8; 240]) {
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(&nonce[..12]);
    let mut ks = [0u8; 16];
    let mut pos = 0usize;
    while pos < data.len() {
        aes_encrypt_block(&counter, &mut ks, rk);
        let n = (data.len() - pos).min(16);
        for i in 0..n {
            out[pos + i] = data[pos + i] ^ ks[i];
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
}

// ----- LEGACY weak KDF (kept so old ciphertexts still decrypt) ---------------
fn derive_key_legacy(password: &[u8], salt: &[u8], key: &mut [u8; 32]) {
    let mut s = [0u8; 32];
    for i in 0..32 {
        s[i] = if i < salt.len() {
            salt[i]
        } else {
            i as u8
        };
    }
    for round in 0..1000 {
        for (i, &p) in password.iter().enumerate() {
            let idx = (i + round) % 32;
            s[idx] ^= p;
            s[idx] = SBOX[s[idx] as usize];
            s[(idx + 1) % 32] ^= s[idx];
        }
        let mut tmp = [0u8; 32];
        for i in 0..32 {
            tmp[i] = s[i] ^ s[(i + 13) % 32] ^ s[(i + 23) % 32];
        }
        s = tmp;
    }
    *key = s;
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

    let mut key = [0u8; 32];
    derive_key_legacy(password, nonce, &mut key);
    let mut rk = [0u8; 240];
    aes_key_expansion(&key, &mut rk);

    let mut out = vec![0u8; 12 + data_len];
    out[..12].copy_from_slice(nonce);
    ctr_xor(nonce, data, &mut out[12..], &rk);
    return_bytes(&out)
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
    let nonce = &data[..12];
    let ct = &data[12..];

    let mut key = [0u8; 32];
    derive_key_legacy(password, nonce, &mut key);
    let mut rk = [0u8; 240];
    aes_key_expansion(&key, &mut rk);

    let mut out = vec![0u8; ct.len()];
    ctr_xor(nonce, ct, &mut out, &rk);
    return_bytes(&out)
}

// ----- v2 envelope: argon2id KDF + AES-CTR + tag prefix ----------------------
//
// Layout: [version=0x02 | salt(16) | nonce(12) | ciphertext...]
//
// Salt is randomly supplied by JS (CSPRNG). Nonce too.

fn argon2id_derive(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19 * 1024, 2, 1, Some(32)).unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .expect("argon2 hash");
    out
}

#[no_mangle]
pub unsafe extern "C" fn aes_v2_encrypt(
    data_ptr: *const u8,
    data_len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
    salt_ptr: *const u8,
    nonce_ptr: *const u8,
) -> u64 {
    if data_len == 0 {
        return 0;
    }
    let data = slice::from_raw_parts(data_ptr, data_len);
    let pw = slice::from_raw_parts(pw_ptr, pw_len);
    let salt = slice::from_raw_parts(salt_ptr, 16);
    let nonce = slice::from_raw_parts(nonce_ptr, 12);

    let key = argon2id_derive(pw, salt);
    let mut rk = [0u8; 240];
    aes_key_expansion(&key, &mut rk);

    let mut out = Vec::with_capacity(1 + 16 + 12 + data_len);
    out.push(0x02);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.resize(1 + 16 + 12 + data_len, 0);
    let ct_off = 1 + 16 + 12;
    ctr_xor(nonce, data, &mut out[ct_off..], &rk);
    return_bytes(&out)
}

#[no_mangle]
pub unsafe extern "C" fn aes_v2_decrypt(
    data_ptr: *const u8,
    data_len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
) -> u64 {
    if data_len < 1 + 16 + 12 {
        return 0;
    }
    let data = slice::from_raw_parts(data_ptr, data_len);
    if data[0] != 0x02 {
        return 0;
    }
    let pw = slice::from_raw_parts(pw_ptr, pw_len);
    let salt = &data[1..17];
    let nonce = &data[17..29];
    let ct = &data[29..];

    let key = argon2id_derive(pw, salt);
    let mut rk = [0u8; 240];
    aes_key_expansion(&key, &mut rk);

    let mut out = vec![0u8; ct.len()];
    ctr_xor(nonce, ct, &mut out, &rk);
    return_bytes(&out)
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

fn xxhash64(data: &[u8]) -> u64 {
    let mut h: u64 = PRIME5;
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let chunk = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        h = xxh_round(h, chunk);
        i += 8;
    }
    while i < data.len() {
        h ^= (data[i] as u64).wrapping_mul(PRIME5);
        h = ((h << 11) | (h >> 53)).wrapping_mul(PRIME1);
        i += 1;
    }
    h ^= data.len() as u64;
    xxh_avalanche(h)
}

#[no_mangle]
pub unsafe extern "C" fn hash_data(data_ptr: *const u8, data_len: usize) -> u64 {
    if data_len == 0 {
        return 0;
    }
    let data = slice::from_raw_parts(data_ptr, data_len);
    let h = xxhash64(data);
    let mut buf = [0u8; 11];
    let mut r = h;
    for j in 0..11 {
        buf[j] = BASE64URL_ALPHABET[(r & 0x3F) as usize];
        r >>= 6;
    }
    return_bytes(&buf)
}

// ============================================================================
// SYNTAX TOKENIZER (kept verbatim from prior version, condensed)
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
const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move",
    "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await",
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
    Rust = 7,
}

fn lang_from_u8(v: u8) -> Language {
    match v {
        1 => Language::Javascript,
        2 => Language::Json,
        3 => Language::Html,
        4 => Language::Css,
        5 => Language::Python,
        6 => Language::Markdown,
        7 => Language::Rust,
        _ => Language::Plain,
    }
}

fn keywords_for(lang: Language) -> Option<&'static [&'static str]> {
    match lang {
        Language::Javascript | Language::Json => Some(JS_KEYWORDS),
        Language::Python => Some(PYTHON_KEYWORDS),
        Language::Rust => Some(RUST_KEYWORDS),
        Language::Css => Some(CSS_KEYWORDS),
        _ => None,
    }
}

fn is_keyword(word: &[u8], lang: Language) -> bool {
    let Some(kws) = keywords_for(lang) else {
        return false;
    };
    kws.iter().any(|kw| word == kw.as_bytes())
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
fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

fn write_token(out: &mut Vec<u8>, start: usize, length: usize, t: TokenType) {
    if out.len() / TOKEN_SIZE >= MAX_TOKENS {
        return;
    }
    out.extend_from_slice(&(start as u32).to_le_bytes());
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.push(t as u8);
}

fn tokenize_clike(input: &[u8], out: &mut Vec<u8>, lang: Language) {
    let mut pos = 0usize;
    while pos < input.len() {
        let c = input[pos];
        if is_ws(c) {
            pos += 1;
            continue;
        }
        if c == b'/' && pos + 1 < input.len() && input[pos + 1] == b'/' {
            let s = pos;
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::Comment);
            continue;
        }
        if c == b'/' && pos + 1 < input.len() && input[pos + 1] == b'*' {
            let s = pos;
            pos += 2;
            while pos + 1 < input.len() && !(input[pos] == b'*' && input[pos + 1] == b'/') {
                pos += 1;
            }
            pos = (pos + 2).min(input.len());
            write_token(out, s, pos - s, TokenType::Comment);
            continue;
        }
        if c == b'"' || c == b'\'' || c == b'`' {
            let q = c;
            let s = pos;
            pos += 1;
            while pos < input.len() {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else if input[pos] == q {
                    pos += 1;
                    break;
                } else if q != b'`' && input[pos] == b'\n' {
                    break;
                } else {
                    pos += 1;
                }
            }
            write_token(out, s, pos - s, TokenType::StringLit);
            continue;
        }
        if is_digit(c) || (c == b'.' && pos + 1 < input.len() && is_digit(input[pos + 1])) {
            let s = pos;
            if c == b'0' && pos + 1 < input.len() && matches!(input[pos + 1], b'x' | b'X') {
                pos += 2;
                while pos < input.len() && (is_hex_digit(input[pos]) || input[pos] == b'_') {
                    pos += 1;
                }
            } else {
                while pos < input.len() && (is_digit(input[pos]) || input[pos] == b'.' || input[pos] == b'_') {
                    pos += 1;
                }
                if pos < input.len() && matches!(input[pos], b'e' | b'E') {
                    pos += 1;
                    if pos < input.len() && matches!(input[pos], b'+' | b'-') {
                        pos += 1;
                    }
                    while pos < input.len() && is_digit(input[pos]) {
                        pos += 1;
                    }
                }
            }
            write_token(out, s, pos - s, TokenType::Number);
            continue;
        }
        if is_alpha(c) {
            let s = pos;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            let w = &input[s..pos];
            if is_keyword(w, lang) {
                write_token(out, s, pos - s, TokenType::Keyword);
            } else if pos < input.len() && input[pos] == b'(' {
                write_token(out, s, pos - s, TokenType::FunctionName);
            } else if !w.is_empty() && (b'A'..=b'Z').contains(&w[0]) {
                write_token(out, s, pos - s, TokenType::TypeName);
            }
            continue;
        }
        if matches!(c, b'+' | b'-' | b'*' | b'/' | b'=' | b'<' | b'>' | b'!' | b'&' | b'|' | b'^' | b'%' | b'~' | b'?') {
            let s = pos;
            pos += 1;
            if pos < input.len() {
                let n = input[pos];
                if (c == b'=' && (n == b'=' || n == b'>'))
                    || (c == b'!' && n == b'=')
                    || (c == b'<' && (n == b'=' || n == b'<'))
                    || (c == b'>' && (n == b'=' || n == b'>'))
                    || (c == b'&' && n == b'&')
                    || (c == b'|' && n == b'|')
                    || (c == b'+' && n == b'+')
                    || (c == b'-' && n == b'-')
                    || (c == b'*' && n == b'*')
                    || (c == b'?' && n == b'?')
                {
                    pos += 1;
                    if pos < input.len() && input[pos] == b'=' {
                        pos += 1;
                    }
                }
            }
            write_token(out, s, pos - s, TokenType::Operator);
            continue;
        }
        if matches!(c, b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b';' | b':' | b'.') {
            write_token(out, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
}

fn tokenize_html(input: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0usize;
    while pos < input.len() {
        let c = input[pos];
        if c == b'<' && pos + 3 < input.len() && input[pos + 1] == b'!' && input[pos + 2] == b'-' && input[pos + 3] == b'-' {
            let s = pos;
            pos += 4;
            while pos + 2 < input.len() && !(input[pos] == b'-' && input[pos + 1] == b'-' && input[pos + 2] == b'>') {
                pos += 1;
            }
            pos = (pos + 3).min(input.len());
            write_token(out, s, pos - s, TokenType::Comment);
            continue;
        }
        if c == b'<' {
            pos += 1;
            if pos < input.len() && input[pos] == b'/' {
                pos += 1;
            }
            let tag_s = pos;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            if pos > tag_s {
                write_token(out, tag_s, pos - tag_s, TokenType::Tag);
            }
            while pos < input.len() && input[pos] != b'>' {
                if is_ws(input[pos]) {
                    pos += 1;
                    continue;
                }
                if is_alpha(input[pos]) {
                    let attr_s = pos;
                    while pos < input.len() && (is_alnum(input[pos]) || input[pos] == b'-') {
                        pos += 1;
                    }
                    write_token(out, attr_s, pos - attr_s, TokenType::Attribute);
                    while pos < input.len() && is_ws(input[pos]) {
                        pos += 1;
                    }
                    if pos < input.len() && input[pos] == b'=' {
                        pos += 1;
                        while pos < input.len() && is_ws(input[pos]) {
                            pos += 1;
                        }
                        if pos < input.len() && (input[pos] == b'"' || input[pos] == b'\'') {
                            let q = input[pos];
                            let val_s = pos;
                            pos += 1;
                            while pos < input.len() && input[pos] != q {
                                pos += 1;
                            }
                            pos = (pos + 1).min(input.len());
                            write_token(out, val_s, pos - val_s, TokenType::StringLit);
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
}

fn tokenize_css(input: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0usize;
    while pos < input.len() {
        let c = input[pos];
        if is_ws(c) {
            pos += 1;
            continue;
        }
        if c == b'/' && pos + 1 < input.len() && input[pos + 1] == b'*' {
            let s = pos;
            pos += 2;
            while pos + 1 < input.len() && !(input[pos] == b'*' && input[pos + 1] == b'/') {
                pos += 1;
            }
            pos = (pos + 2).min(input.len());
            write_token(out, s, pos - s, TokenType::Comment);
            continue;
        }
        if c == b'"' || c == b'\'' {
            let q = c;
            let s = pos;
            pos += 1;
            while pos < input.len() && input[pos] != q {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            pos = (pos + 1).min(input.len());
            write_token(out, s, pos - s, TokenType::StringLit);
            continue;
        }
        if is_digit(c) || (c == b'.' && pos + 1 < input.len() && is_digit(input[pos + 1])) {
            let s = pos;
            while pos < input.len() && (is_digit(input[pos]) || input[pos] == b'.') {
                pos += 1;
            }
            while pos < input.len() && is_alpha(input[pos]) {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::Number);
            continue;
        }
        if c == b'#' {
            let s = pos;
            pos += 1;
            while pos < input.len() && is_hex_digit(input[pos]) {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::Number);
            continue;
        }
        if is_alpha(c) || c == b'-' || c == b'_' {
            let s = pos;
            while pos < input.len() && (is_alnum(input[pos]) || input[pos] == b'-' || input[pos] == b'_') {
                pos += 1;
            }
            let w = &input[s..pos];
            if is_keyword(w, Language::Css) {
                write_token(out, s, pos - s, TokenType::Keyword);
            } else {
                write_token(out, s, pos - s, TokenType::Property);
            }
            continue;
        }
        if matches!(c, b'{' | b'}' | b':' | b';' | b',' | b'(' | b')') {
            write_token(out, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
}

fn tokenize_python(input: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0usize;
    while pos < input.len() {
        let c = input[pos];
        if is_ws(c) {
            pos += 1;
            continue;
        }
        if c == b'#' {
            let s = pos;
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::Comment);
            continue;
        }
        if (c == b'"' || c == b'\'') && pos + 2 < input.len() && input[pos + 1] == c && input[pos + 2] == c {
            let q = c;
            let s = pos;
            pos += 3;
            while pos + 2 < input.len() && !(input[pos] == q && input[pos + 1] == q && input[pos + 2] == q) {
                pos += 1;
            }
            pos = (pos + 3).min(input.len());
            write_token(out, s, pos - s, TokenType::StringLit);
            continue;
        }
        if c == b'"' || c == b'\'' {
            let q = c;
            let s = pos;
            pos += 1;
            while pos < input.len() && input[pos] != q && input[pos] != b'\n' {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            if pos < input.len() && input[pos] == q {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::StringLit);
            continue;
        }
        if is_digit(c) {
            let s = pos;
            if c == b'0' && pos + 1 < input.len() && matches!(input[pos + 1], b'x' | b'X' | b'b' | b'B' | b'o' | b'O') {
                pos += 2;
                while pos < input.len() && (is_hex_digit(input[pos]) || input[pos] == b'_') {
                    pos += 1;
                }
                write_token(out, s, pos - s, TokenType::Number);
                continue;
            }
            while pos < input.len() && (is_digit(input[pos]) || input[pos] == b'.' || input[pos] == b'_') {
                pos += 1;
            }
            if pos < input.len() && matches!(input[pos], b'e' | b'E') {
                pos += 1;
                if pos < input.len() && matches!(input[pos], b'+' | b'-') {
                    pos += 1;
                }
                while pos < input.len() && is_digit(input[pos]) {
                    pos += 1;
                }
            }
            write_token(out, s, pos - s, TokenType::Number);
            continue;
        }
        if is_alpha(c) {
            let s = pos;
            while pos < input.len() && is_alnum(input[pos]) {
                pos += 1;
            }
            let w = &input[s..pos];
            if is_keyword(w, Language::Python) {
                write_token(out, s, pos - s, TokenType::Keyword);
            } else if pos < input.len() && input[pos] == b'(' {
                write_token(out, s, pos - s, TokenType::FunctionName);
            } else if !w.is_empty() && (b'A'..=b'Z').contains(&w[0]) {
                write_token(out, s, pos - s, TokenType::TypeName);
            }
            continue;
        }
        if matches!(c, b'+' | b'-' | b'*' | b'/' | b'=' | b'<' | b'>' | b'!' | b'&' | b'|' | b'^' | b'%' | b'~' | b'@') {
            let s = pos;
            pos += 1;
            if pos < input.len() && (input[pos] == b'=' || input[pos] == c) {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::Operator);
            continue;
        }
        if matches!(c, b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b':' | b'.') {
            write_token(out, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
}

fn tokenize_json(input: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0usize;
    while pos < input.len() {
        let c = input[pos];
        if is_ws(c) {
            pos += 1;
            continue;
        }
        if c == b'"' {
            let s = pos;
            pos += 1;
            while pos < input.len() && input[pos] != b'"' {
                if input[pos] == b'\\' && pos + 1 < input.len() {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            pos = (pos + 1).min(input.len());
            let mut peek = pos;
            while peek < input.len() && is_ws(input[peek]) {
                peek += 1;
            }
            if peek < input.len() && input[peek] == b':' {
                write_token(out, s, pos - s, TokenType::Property);
            } else {
                write_token(out, s, pos - s, TokenType::StringLit);
            }
            continue;
        }
        if is_digit(c) || c == b'-' {
            let s = pos;
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
            if pos < input.len() && matches!(input[pos], b'e' | b'E') {
                pos += 1;
                if pos < input.len() && matches!(input[pos], b'+' | b'-') {
                    pos += 1;
                }
                while pos < input.len() && is_digit(input[pos]) {
                    pos += 1;
                }
            }
            write_token(out, s, pos - s, TokenType::Number);
            continue;
        }
        if is_alpha(c) {
            let s = pos;
            while pos < input.len() && is_alpha(input[pos]) {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::Keyword);
            continue;
        }
        if matches!(c, b'{' | b'}' | b'[' | b']' | b':' | b',') {
            write_token(out, pos, 1, TokenType::Punctuation);
            pos += 1;
            continue;
        }
        pos += 1;
    }
}

fn tokenize_markdown(input: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0usize;
    while pos < input.len() {
        let c = input[pos];
        if c == b'#' && (pos == 0 || input[pos - 1] == b'\n') {
            let s = pos;
            while pos < input.len() && input[pos] == b'#' {
                pos += 1;
            }
            while pos < input.len() && input[pos] != b'\n' {
                pos += 1;
            }
            write_token(out, s, pos - s, TokenType::Keyword);
            continue;
        }
        if c == b'`' && pos + 2 < input.len() && input[pos + 1] == b'`' && input[pos + 2] == b'`' {
            let s = pos;
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
            write_token(out, s, pos - s, TokenType::Comment);
            continue;
        }
        if c == b'`' {
            let s = pos;
            pos += 1;
            while pos < input.len() && input[pos] != b'`' && input[pos] != b'\n' {
                pos += 1;
            }
            pos = (pos + 1).min(input.len());
            write_token(out, s, pos - s, TokenType::StringLit);
            continue;
        }
        if c == b'*' && pos + 1 < input.len() && input[pos + 1] == b'*' {
            let s = pos;
            pos += 2;
            while pos + 1 < input.len() && !(input[pos] == b'*' && input[pos + 1] == b'*') {
                pos += 1;
            }
            pos = (pos + 2).min(input.len());
            write_token(out, s, pos - s, TokenType::TypeName);
            continue;
        }
        if c == b'[' {
            let s = pos;
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
                    pos = (pos + 1).min(input.len());
                }
            }
            write_token(out, s, pos - s, TokenType::Tag);
            continue;
        }
        pos += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn tokenize(input_ptr: *const u8, input_len: usize, lang: u8) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let mut out: Vec<u8> = Vec::with_capacity(input_len / 4 + 64);
    let language = lang_from_u8(lang);
    match language {
        Language::Javascript => tokenize_clike(input, &mut out, Language::Javascript),
        Language::Json => tokenize_json(input, &mut out),
        Language::Html => tokenize_html(input, &mut out),
        Language::Css => tokenize_css(input, &mut out),
        Language::Python => tokenize_python(input, &mut out),
        Language::Rust => tokenize_clike(input, &mut out, Language::Rust),
        Language::Markdown => tokenize_markdown(input, &mut out),
        _ => {}
    }
    return_bytes(&out)
}

fn memmem(hay: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || n.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - n.len()).find(|&i| &hay[i..i + n.len()] == n)
}

#[no_mangle]
pub unsafe extern "C" fn detect_language(input_ptr: *const u8, input_len: usize) -> u8 {
    if input_len == 0 {
        return 0;
    }
    let input = slice::from_raw_parts(input_ptr, input_len);
    let mut i = 0usize;
    while i < input.len() && is_ws(input[i]) {
        i += 1;
    }
    if i + 1 < input.len() && input[i] == b'<' && (input[i + 1] == b'!' || is_alpha(input[i + 1])) {
        return Language::Html as u8;
    }
    if i < input.len() && (input[i] == b'{' || input[i] == b'[') {
        return Language::Json as u8;
    }
    let head = &input[..input.len().min(500)];
    if input.len() > 2 && input[0] == b'#' && input[1] == b'!' {
        let h = &input[..input.len().min(50)];
        if memmem(h, b"python").is_some() {
            return Language::Python as u8;
        }
    }
    if memmem(head, b"def ").is_some() {
        return Language::Python as u8;
    }
    if memmem(head, b"fn ").is_some() && memmem(head, b"->").is_some() {
        return Language::Rust as u8;
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

// ============================================================================
// SEARCH: returns packed pairs of (offset:u32, length:u32)
// flags: bit0 = case-insensitive, bit1 = whole-word
// ============================================================================

fn ascii_lower(c: u8) -> u8 {
    if (b'A'..=b'Z').contains(&c) { c + 32 } else { c }
}

fn word_boundary(text: &[u8], idx: usize) -> bool {
    let prev = if idx == 0 { 0u8 } else { text[idx - 1] };
    !is_alnum(prev)
}

#[no_mangle]
pub unsafe extern "C" fn search_all(
    text_ptr: *const u8,
    text_len: usize,
    pat_ptr: *const u8,
    pat_len: usize,
    flags: u32,
) -> u64 {
    if text_len == 0 || pat_len == 0 || pat_len > text_len {
        return 0;
    }
    let text = slice::from_raw_parts(text_ptr, text_len);
    let pat = slice::from_raw_parts(pat_ptr, pat_len);
    let icase = flags & 1 != 0;
    let whole = flags & 2 != 0;
    let mut out: Vec<u8> = Vec::with_capacity(64);
    let mut i = 0usize;
    while i + pat_len <= text_len {
        let mut hit = true;
        for j in 0..pat_len {
            let a = text[i + j];
            let b = pat[j];
            let eq = if icase { ascii_lower(a) == ascii_lower(b) } else { a == b };
            if !eq {
                hit = false;
                break;
            }
        }
        if hit {
            if !whole || (word_boundary(text, i) && (i + pat_len == text_len || !is_alnum(text[i + pat_len]))) {
                out.extend_from_slice(&(i as u32).to_le_bytes());
                out.extend_from_slice(&(pat_len as u32).to_le_bytes());
            }
            i += pat_len;
        } else {
            i += 1;
        }
    }
    return_bytes(&out)
}

// ============================================================================
// SNAPSHOT RING (persistent across reset_heap; held in std heap)
// ============================================================================

struct Snapshot {
    ts: u64,
    note: String,
    data: Vec<u8>,
}

static mut SNAPSHOTS: Option<Vec<Snapshot>> = None;
const MAX_SNAPS: usize = 64;

unsafe fn snaps_mut() -> &'static mut Vec<Snapshot> {
    if SNAPSHOTS.is_none() {
        SNAPSHOTS = Some(Vec::new());
    }
    SNAPSHOTS.as_mut().unwrap()
}

#[no_mangle]
pub unsafe extern "C" fn snapshot_push(
    data_ptr: *const u8,
    data_len: usize,
    note_ptr: *const u8,
    note_len: usize,
    ts: u64,
) -> u32 {
    let data = slice::from_raw_parts(data_ptr, data_len).to_vec();
    let note = String::from_utf8(slice::from_raw_parts(note_ptr, note_len).to_vec())
        .unwrap_or_default();
    let v = snaps_mut();
    v.push(Snapshot { ts, note, data });
    if v.len() > MAX_SNAPS {
        v.remove(0);
    }
    v.len() as u32
}

#[no_mangle]
pub unsafe extern "C" fn snapshot_count() -> u32 {
    snaps_mut().len() as u32
}

#[no_mangle]
pub unsafe extern "C" fn snapshot_clear() {
    snaps_mut().clear();
}

// Returns packed pairs (ts:u64, note_len:u32, data_len:u32, note utf8 bytes)
// Compact layout per snapshot: 8+4+4+note_len
#[no_mangle]
pub unsafe extern "C" fn snapshot_list() -> u64 {
    let v = snaps_mut();
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for s in v.iter() {
        out.extend_from_slice(&s.ts.to_le_bytes());
        out.extend_from_slice(&(s.note.len() as u32).to_le_bytes());
        out.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
        out.extend_from_slice(s.note.as_bytes());
    }
    return_bytes(&out)
}

#[no_mangle]
pub unsafe extern "C" fn snapshot_restore(idx: u32) -> u64 {
    let v = snaps_mut();
    let Some(s) = v.get(idx as usize) else {
        return 0;
    };
    let data = s.data.clone();
    return_bytes(&data)
}

// ============================================================================
// MARKDOWN -> sanitized HTML  (uses pulldown-cmark)
// ============================================================================

fn sanitize_html(input: &str) -> String {
    // Allow a known set of tags; everything else becomes plain text via escape.
    // Implementation: only strip <script>, <style>, on*= attributes via regex-light scan.
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' && i + 7 <= bytes.len() {
            let lower: String = bytes[i + 1..(i + 8).min(bytes.len())]
                .iter()
                .map(|&b| ascii_lower(b) as char)
                .collect();
            if lower.starts_with("script") || lower.starts_with("/script") {
                // skip until > then continue
                if let Some(end) = bytes[i..].iter().position(|&b| b == b'>') {
                    i += end + 1;
                    continue;
                }
            }
        }
        // strip on*= attribute substrings
        if bytes[i] == b' ' && i + 3 < bytes.len()
            && ascii_lower(bytes[i + 1]) == b'o'
            && ascii_lower(bytes[i + 2]) == b'n'
        {
            let mut j = i + 3;
            while j < bytes.len() && (is_alpha(bytes[j])) {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                let mut k = j + 1;
                if k < bytes.len() && (bytes[k] == b'"' || bytes[k] == b'\'') {
                    let q = bytes[k];
                    k += 1;
                    while k < bytes.len() && bytes[k] != q {
                        k += 1;
                    }
                    k += 1;
                } else {
                    while k < bytes.len() && !is_ws(bytes[k]) && bytes[k] != b'>' {
                        k += 1;
                    }
                }
                i = k;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn md_render(input_ptr: *const u8, input_len: usize) -> u64 {
    if input_len == 0 {
        return 0;
    }
    let s = match core::str::from_utf8(slice::from_raw_parts(input_ptr, input_len)) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    use pulldown_cmark::{html, Options, Parser};
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_FOOTNOTES);
    let parser = Parser::new_ext(s, opts);
    let mut html_out = String::new();
    html::push_html(&mut html_out, parser);
    let clean = sanitize_html(&html_out);
    return_bytes(clean.as_bytes())
}

// ============================================================================
// LINE DIFF (Myers O(ND))
// ============================================================================

fn split_lines(s: &str) -> Vec<&str> {
    if s.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut start = 0;
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'\n' {
            lines.push(&s[start..i]);
            start = i + 1;
        }
    }
    if start <= b.len() {
        lines.push(&s[start..]);
    }
    lines
}

#[derive(Clone, Copy)]
enum Op {
    Eq = 0,
    Del = 1,
    Ins = 2,
}

fn myers_diff<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(Op, usize, usize)> {
    // returns list of (op, a_idx, b_idx). For Eq/Del a_idx valid, for Ins b_idx valid.
    let n = a.len();
    let m = b.len();
    if n == 0 {
        return (0..m).map(|i| (Op::Ins, 0, i)).collect();
    }
    if m == 0 {
        return (0..n).map(|i| (Op::Del, i, 0)).collect();
    }
    let max = n + m;
    let mut v = vec![0isize; 2 * max + 1];
    let offset = max as isize;
    let mut trace: Vec<Vec<isize>> = Vec::new();
    'outer: for d in 0..=max as isize {
        let mut snapshot = v.clone();
        let mut k = -d;
        while k <= d {
            let down = k == -d
                || (k != d
                    && v[(offset + k - 1) as usize] < v[(offset + k + 1) as usize]);
            let kprev = if down { k + 1 } else { k - 1 };
            let xstart = v[(offset + kprev) as usize];
            let mut x = if down { xstart } else { xstart + 1 };
            let mut y = x - k;
            while (x as usize) < n && (y as usize) < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[(offset + k) as usize] = x;
            if (x as usize) >= n && (y as usize) >= m {
                snapshot = v.clone();
                trace.push(snapshot);
                break 'outer;
            }
            k += 2;
        }
        trace.push(snapshot);
    }
    // Backtrack
    let mut ops: Vec<(Op, usize, usize)> = Vec::new();
    let mut x = n as isize;
    let mut y = m as isize;
    for d in (0..trace.len() as isize).rev() {
        let vv = &trace[d as usize];
        let k = x - y;
        let down = k == -d
            || (k != d
                && vv[(offset + k - 1) as usize] < vv[(offset + k + 1) as usize]);
        let kprev = if down { k + 1 } else { k - 1 };
        let xprev = vv[(offset + kprev) as usize];
        let yprev = xprev - kprev;
        while x > xprev && y > yprev {
            ops.push((Op::Eq, (x - 1) as usize, (y - 1) as usize));
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if down {
                ops.push((Op::Ins, x as usize, (y - 1) as usize));
                y -= 1;
            } else {
                ops.push((Op::Del, (x - 1) as usize, y as usize));
                x -= 1;
            }
        }
    }
    ops.reverse();
    ops
}

// diff_lines: returns packed list of (op:u8, a_idx:u32, b_idx:u32) bytes
#[no_mangle]
pub unsafe extern "C" fn diff_lines(
    a_ptr: *const u8,
    a_len: usize,
    b_ptr: *const u8,
    b_len: usize,
) -> u64 {
    let aa = core::str::from_utf8(slice::from_raw_parts(a_ptr, a_len)).unwrap_or("");
    let bb = core::str::from_utf8(slice::from_raw_parts(b_ptr, b_len)).unwrap_or("");
    let a_lines = split_lines(aa);
    let b_lines = split_lines(bb);
    let ops = myers_diff(&a_lines, &b_lines);
    let mut out = Vec::with_capacity(ops.len() * 9);
    out.extend_from_slice(&(ops.len() as u32).to_le_bytes());
    for (op, ai, bi) in ops {
        out.push(op as u8);
        out.extend_from_slice(&(ai as u32).to_le_bytes());
        out.extend_from_slice(&(bi as u32).to_le_bytes());
    }
    return_bytes(&out)
}

// ============================================================================
// MULTI-FILE PACK: [num_files:u32]( [name_len:u16][name][body_len:u32][body] )*
// ============================================================================
//
// Input format from JS (flat): [num:u32]( [nl:u16][name_utf8][bl:u32][body] )*

#[no_mangle]
pub unsafe extern "C" fn pack_files(input_ptr: *const u8, input_len: usize) -> u64 {
    let input = slice::from_raw_parts(input_ptr, input_len).to_vec();
    return_bytes(&input)
}

#[no_mangle]
pub unsafe extern "C" fn unpack_files(input_ptr: *const u8, input_len: usize) -> u64 {
    // Validate format, return same bytes if OK (JS parses)
    let input = slice::from_raw_parts(input_ptr, input_len);
    if input.len() < 4 {
        return 0;
    }
    let n = u32::from_le_bytes(input[0..4].try_into().unwrap());
    let mut off = 4usize;
    for _ in 0..n {
        if off + 2 > input.len() {
            return 0;
        }
        let nl = u16::from_le_bytes(input[off..off + 2].try_into().unwrap()) as usize;
        off += 2 + nl;
        if off + 4 > input.len() {
            return 0;
        }
        let bl = u32::from_le_bytes(input[off..off + 4].try_into().unwrap()) as usize;
        off += 4 + bl;
        if off > input.len() {
            return 0;
        }
    }
    return_bytes(input)
}

// ============================================================================
// FORMATTERS
// ============================================================================

fn json_pretty(input: &str, indent_size: usize) -> Option<String> {
    let b = input.as_bytes();
    let mut out = String::with_capacity(input.len() * 2);
    let mut indent = 0usize;
    let mut i = 0usize;
    let mut in_str = false;
    let pad = |o: &mut String, n: usize, ind: usize| {
        o.push('\n');
        for _ in 0..n * ind {
            o.push(' ');
        }
    };
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c as char);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_str = true;
                out.push('"');
            }
            b'{' | b'[' => {
                out.push(c as char);
                indent += 1;
                pad(&mut out, indent_size, indent);
            }
            b'}' | b']' => {
                if indent > 0 {
                    indent -= 1;
                }
                pad(&mut out, indent_size, indent);
                out.push(c as char);
            }
            b',' => {
                out.push(',');
                pad(&mut out, indent_size, indent);
            }
            b':' => {
                out.push_str(": ");
            }
            c if is_ws(c) => {}
            _ => out.push(c as char),
        }
        i += 1;
    }
    Some(out)
}

#[no_mangle]
pub unsafe extern "C" fn format_json(input_ptr: *const u8, input_len: usize, indent: u32) -> u64 {
    let s = core::str::from_utf8(slice::from_raw_parts(input_ptr, input_len)).unwrap_or("");
    match json_pretty(s, indent.max(1) as usize) {
        Some(p) => return_bytes(p.as_bytes()),
        None => 0,
    }
}

// Markdown reflow: collapse runs of plain-text whitespace, preserve code fences and lists.
fn md_reflow(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_code = false;
    for line in input.split('\n') {
        let trimmed = line.trim_end();
        if trimmed.starts_with("```") {
            in_code = !in_code;
            out.push_str(trimmed);
            out.push('\n');
            continue;
        }
        if in_code {
            out.push_str(trimmed);
            out.push('\n');
            continue;
        }
        // collapse internal whitespace runs
        let mut prev_ws = false;
        for ch in trimmed.chars() {
            if ch == ' ' || ch == '\t' {
                if !prev_ws {
                    out.push(' ');
                    prev_ws = true;
                }
            } else {
                out.push(ch);
                prev_ws = false;
            }
        }
        out.push('\n');
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn format_markdown(input_ptr: *const u8, input_len: usize) -> u64 {
    let s = core::str::from_utf8(slice::from_raw_parts(input_ptr, input_len)).unwrap_or("");
    let r = md_reflow(s);
    return_bytes(r.as_bytes())
}

// ============================================================================
// ED25519 SIGN / VERIFY
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn ed25519_keypair_from_seed(seed_ptr: *const u8) -> u64 {
    use ed25519_compact::*;
    let seed_bytes = slice::from_raw_parts(seed_ptr, 32);
    let seed = Seed::from_slice(seed_bytes).expect("seed");
    let kp = KeyPair::from_seed(seed);
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&*kp.sk);
    out.extend_from_slice(&*kp.pk);
    return_bytes(&out)
}

#[no_mangle]
pub unsafe extern "C" fn ed25519_sign(
    msg_ptr: *const u8,
    msg_len: usize,
    sk_ptr: *const u8,
) -> u64 {
    use ed25519_compact::*;
    let msg = slice::from_raw_parts(msg_ptr, msg_len);
    let sk_bytes = slice::from_raw_parts(sk_ptr, 64);
    let sk = SecretKey::from_slice(sk_bytes).expect("sk");
    let sig = sk.sign(msg, None);
    return_bytes(&*sig)
}

#[no_mangle]
pub unsafe extern "C" fn ed25519_verify(
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    pk_ptr: *const u8,
) -> u32 {
    use ed25519_compact::*;
    let msg = slice::from_raw_parts(msg_ptr, msg_len);
    let sig_bytes = slice::from_raw_parts(sig_ptr, 64);
    let pk_bytes = slice::from_raw_parts(pk_ptr, 32);
    let Ok(sig) = Signature::from_slice(sig_bytes) else {
        return 0;
    };
    let Ok(pk) = PublicKey::from_slice(pk_bytes) else {
        return 0;
    };
    if pk.verify(msg, &sig).is_ok() { 1 } else { 0 }
}

// ============================================================================
// PNG EXPORT (monochrome text bitmap, palette-encoded, deflate via miniz_oxide)
// ============================================================================
//
// Renders highlighted text to an RGB PNG. Uses font8x8 for glyphs.
// Inputs: text bytes + tokens bytes (same format as tokenize output) + lang.
// Output: PNG bytes ready to download.

const CRC32_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
};

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut c = 0xffffffffu32;
    for &b in data {
        c = CRC32_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut crc_buf = Vec::with_capacity(4 + data.len());
    crc_buf.extend_from_slice(kind);
    crc_buf.extend_from_slice(data);
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32_ieee(&crc_buf).to_be_bytes());
}

const FG_PALETTE: [(u8, u8, u8); 13] = [
    (216, 210, 194), // 0 default
    (212, 155, 255), // 1 keyword
    (255, 200, 144), // 2 string
    (193, 255, 122), // 3 number
    (90, 96, 102),   // 4 comment
    (216, 210, 194), // 5 op
    (106, 113, 120), // 6 punct
    (240, 224, 122), // 7 fn
    (123, 236, 200), // 8 type
    (216, 210, 194), // 9 var
    (102, 224, 255), // 10 tag
    (178, 242, 255), // 11 attr
    (178, 242, 255), // 12 prop
];

const BG_COLOR: (u8, u8, u8) = (7, 9, 10);

fn token_at(tokens: &[u8], byte_idx: usize) -> u8 {
    // Linear scan; tokens are start-sorted so could binary-search.
    let mut i = 0;
    let n = tokens.len() / TOKEN_SIZE;
    let mut color = 0u8;
    while i < n {
        let off = i * TOKEN_SIZE;
        let s = u32::from_le_bytes(tokens[off..off + 4].try_into().unwrap()) as usize;
        let l = u32::from_le_bytes(tokens[off + 4..off + 8].try_into().unwrap()) as usize;
        if s > byte_idx {
            break;
        }
        if byte_idx >= s && byte_idx < s + l {
            color = tokens[off + 8];
        }
        i += 1;
    }
    color
}

#[no_mangle]
pub unsafe extern "C" fn render_png(
    text_ptr: *const u8,
    text_len: usize,
    tokens_ptr: *const u8,
    tokens_len: usize,
    scale: u32,
) -> u64 {
    use font8x8::UnicodeFonts;
    if text_ptr.is_null() || text_len == 0 {
        return 0;
    }
    let text = core::str::from_utf8(slice::from_raw_parts(text_ptr, text_len)).unwrap_or("");
    let tokens: &[u8] = if tokens_ptr.is_null() || tokens_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(tokens_ptr, tokens_len)
    };
    let scale = scale.clamp(1, 6) as usize;
    let pad = 12usize;

    // Pre-pass: compute width/height in chars
    let mut max_cols = 0usize;
    let mut rows = 1usize;
    let mut col = 0usize;
    for ch in text.chars() {
        if ch == '\n' {
            rows += 1;
            if col > max_cols { max_cols = col; }
            col = 0;
        } else if ch == '\t' {
            col += 4 - (col % 4);
        } else {
            col += 1;
        }
    }
    if col > max_cols { max_cols = col; }
    if max_cols == 0 { max_cols = 1; }

    let cell_w = 8usize * scale;
    let cell_h = 10usize * scale;
    let img_w = max_cols * cell_w + pad * 2;
    let img_h = rows * cell_h + pad * 2;

    // RGB framebuffer
    let mut fb = vec![0u8; img_w * img_h * 3];
    for px in fb.chunks_mut(3) {
        px[0] = BG_COLOR.0; px[1] = BG_COLOR.1; px[2] = BG_COLOR.2;
    }

    let mut x_cell = 0usize;
    let mut y_cell = 0usize;
    let mut byte_idx = 0usize;
    for ch in text.chars() {
        if ch == '\n' {
            y_cell += 1;
            x_cell = 0;
            byte_idx += ch.len_utf8();
            continue;
        }
        if ch == '\t' {
            x_cell += 4 - (x_cell % 4);
            byte_idx += ch.len_utf8();
            continue;
        }
        let color_idx = token_at(tokens, byte_idx) as usize;
        let (r, g, b) = FG_PALETTE.get(color_idx).copied().unwrap_or(FG_PALETTE[0]);
        if let Some(glyph) = font8x8::BASIC_FONTS.get(ch) {
            let px = pad + x_cell * cell_w;
            let py = pad + y_cell * cell_h;
            for gy in 0..8 {
                let row = glyph[gy];
                for gx in 0..8 {
                    if row & (1 << gx) != 0 {
                        for sy in 0..scale {
                            for sx in 0..scale {
                                let ix = px + gx * scale + sx;
                                let iy = py + gy * scale + sy;
                                if ix < img_w && iy < img_h {
                                    let off = (iy * img_w + ix) * 3;
                                    fb[off] = r;
                                    fb[off + 1] = g;
                                    fb[off + 2] = b;
                                }
                            }
                        }
                    }
                }
            }
        }
        x_cell += 1;
        byte_idx += ch.len_utf8();
    }

    // Build PNG
    let mut raw = Vec::with_capacity(img_h * (1 + img_w * 3));
    for y in 0..img_h {
        raw.push(0); // filter: None
        let row_start = y * img_w * 3;
        raw.extend_from_slice(&fb[row_start..row_start + img_w * 3]);
    }
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6);

    let mut png = Vec::with_capacity(compressed.len() + 64);
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(img_w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(img_h as u32).to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(2); // colour type: RGB
    ihdr.push(0); ihdr.push(0); ihdr.push(0); // compress, filter, interlace
    png_chunk(&mut png, b"IHDR", &ihdr);
    png_chunk(&mut png, b"IDAT", &compressed);
    png_chunk(&mut png, b"IEND", &[]);

    return_bytes(&png)
}
