use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, ExprLit, ItemFn, Lit, Meta};

#[proc_macro_attribute]
pub fn oscal_control(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Parse attribute argument: #[oscal_control("SI-7(1)")] or #[oscal_control(id = "SI-7(1)")]
    let control_id = if attr.is_empty() {
        "UNKNOWN-CONTROL".to_string()
    } else {
        let meta = parse_macro_input!(attr as Meta);
        match meta {
            Meta::Path(_) => "UNKNOWN-CONTROL".to_string(),
            Meta::List(list) => {
                let s = list.tokens.to_string();
                s.trim_matches('"').to_string()
            }
            Meta::NameValue(nv) => {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = nv.value
                {
                    s.value()
                } else {
                    "UNKNOWN-CONTROL".to_string()
                }
            }
        }
    };

    let expanded = quote! {
        #input_fn

        ::oscal_types::inventory::submit! {
            ::oscal_types::OscalControlRegistration::new(
                #control_id,
                #fn_name_str,
                file!(),
                line!(),
            )
        }
    };

    TokenStream::from(expanded)
}
