// Golden macro expansion for #[oscal_control(id = "SI-7(1)")]
// Extracted via `cargo +nightly-2026-09-17 rustc -p sha256-demo --lib -- -Zunpretty=expanded`
// DO NOT EDIT MANUALLY - Checked by `xtask verify-provenance`

pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    if !data.is_empty() { digest[0] = data[0]; }
    digest
}

#[allow(non_upper_case_globals)]
const _: () =
    {
        static __INVENTORY: ::inventory::Node =
            ::inventory::Node {
                value: &{
                        ::oscal_types::OscalControlRegistration::new("SI-7(1)",
                            "compute_sha256", "tests/fixtures/sha256-demo/src/lib.rs",
                            3u32)
                    },
                next: ::inventory::__private::UnsafeCell::new(::inventory::__private::Option::None),
            };
        #[link_section = ".text.startup"]
        unsafe extern "C" fn __ctor() {
            unsafe {
                ::inventory::ErasedNode::submit(__INVENTORY.value,
                    &__INVENTORY)
            }
        }
        #[used]
        #[link_section = ".init_array"]
        static __CTOR: unsafe extern "C" fn() = __ctor;
    };
