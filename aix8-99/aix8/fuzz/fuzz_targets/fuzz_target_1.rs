#![no_main]

use libfuzzer_sys::fuzz_target;
use aix8_lib::decrypt_bytes;

fuzz_target!(|data: &[u8]| {

    let _ = decrypt_bytes(data, "fuzz-password");

});