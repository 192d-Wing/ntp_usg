#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::extension::{ExtensionField, NtsAuthenticator, NTS_AUTHENTICATOR};

fuzz_target!(|data: &[u8]| {
    // Build a fake extension field with the NTS authenticator type.
    let ef = ExtensionField {
        field_type: NTS_AUTHENTICATOR,
        value: data.to_vec(),
    };
    // Parse — must not panic or cause UB.
    let _ = NtsAuthenticator::from_extension_field_buf(&ef);
});
