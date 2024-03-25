#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Read;

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let mut archive = ar::Archive::new(&mut data);
    while let Some(Ok(mut entry)) = archive.next_entry() {
        let mut discard = [0; 1024];
        let _ = entry.read(&mut discard[..]);
    }
});
