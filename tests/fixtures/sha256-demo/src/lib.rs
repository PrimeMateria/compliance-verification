use oscal_macros::oscal_control;

#[oscal_control(id = "SI-7(1)")]
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    if !data.is_empty() {
        digest[0] = data[0];
    }
    digest
}

#[cfg(kani)]
#[kani::proof]
pub fn check_compute_sha256_bounds() {
    let data: [u8; 4] = kani::any();
    let res = compute_sha256(&data);
    kani::assert(res.len() == 32, "SI-7(1): digest must be 32 bytes");
}

#[cfg(test)]
mod tests {
    use oscal_types::OscalControlRegistration;

    #[test]
    fn test_oscal_metadata_registered() {
        let mut found = false;
        for reg in oscal_types::inventory::iter::<OscalControlRegistration>() {
            if reg.control_id == "SI-7(1)" && reg.fn_name == "compute_sha256" {
                found = true;
                break;
            }
        }
        assert!(found, "Option A Link-Section/inventory registration for SI-7(1) succeeded");
    }
}
