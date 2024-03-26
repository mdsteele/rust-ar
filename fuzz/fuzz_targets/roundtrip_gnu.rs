#![no_main]

use ar_fuzz::{Entry, Header, Model};
use arbitrary::{Arbitrary as _, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::io::Read as _;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let model = Model::arbitrary(&mut u).expect("make arbitrary model");

    if model.entries.is_empty() {
        return; // Builder does not do anything unless there is at least one entry
    }

    let mut buffer = Vec::new();

    let mut builder = ar::GnuBuilder::new(&mut buffer, model.identifiers());
    for entry in &model.entries {
        if let Err(err) = builder.append(&entry.header(), &mut &entry.data[..])
        {
            panic!("append entry: {err} with {model:?}"); // Or just return if invalid input
        }
    }

    let mut rountripped = Model::default();
    let mut reader = &buffer[..];
    let mut archive = ar::Archive::new(&mut reader);
    while let Some(entry) = archive.next_entry() {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(err) => panic!("read entry: {err} with {model:?}"),
        };
        rountripped.entries.push(Entry {
            header: Header::from_ar(entry.header()),
            data: {
                let mut data = Vec::new();
                if let Err(err) = entry.read_to_end(&mut data) {
                    panic!("read entry data: {err} with {model:?}");
                }
                data
            },
        })
    }

    assert_eq!(model, rountripped);
});
