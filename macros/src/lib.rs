use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Lit, Meta, Type, TypePath, parse_macro_input};

/// Derive macro for creating type-safe secret schemas.
///
/// # Example
///
/// ```ignore
/// use oo7::SecretSchema;
///
/// #[derive(SecretSchema, Debug)]
/// #[schema(name = "org.example.Password")]
/// struct PasswordSchema {
///     username: String,
///     server: String,
///     port: Option<u16>,
///     protocol: Option<String>,
/// }
/// ```
///
/// Use `dont_match_name` to exclude `xdg:schema` from search queries, matching
/// libsecret's `SECRET_SCHEMA_DONT_MATCH_NAME` behavior:
///
/// ```ignore
/// #[derive(SecretSchema, Debug)]
/// #[schema(name = "org.example.Password", dont_match_name)]
/// struct PasswordSchema { /* ... */ }
/// ```
#[proc_macro_derive(SecretSchema, attributes(schema))]
pub fn derive_secret_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let (schema_name, dont_match_name) = match extract_schema_config(&input.attrs) {
        Some(config) => config,
        None => {
            return syn::Error::new_spanned(
                &input,
                "SecretSchema requires #[schema(name = \"...\")] attribute",
            )
            .to_compile_error()
            .into();
        }
    };

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return syn::Error::new_spanned(
                    &input,
                    "SecretSchema only supports structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(&input, "SecretSchema only supports structs")
                .to_compile_error()
                .into();
        }
    };

    let mut as_attributes_fields = Vec::new();
    let mut from_hashmap_fields = Vec::new();
    let mut default_fields = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_name_str = field_name.to_string();
        let is_optional = is_option_type(&field.ty);

        if is_optional {
            as_attributes_fields.push(quote! {
                if let Some(ref value) = self.#field_name {
                    owned.insert(#field_name_str.to_string(), value.to_string());
                }
            });

            let inner_type = extract_option_inner_type(&field.ty);
            from_hashmap_fields.push(quote! {
                #field_name: attrs.get(#field_name_str)
                    .map(|v| {
                        v.parse::<#inner_type>()
                            .map_err(|_| ::oo7::SchemaError::InvalidValue {
                                field: #field_name_str,
                                value: v.to_string(),
                            })
                    })
                    .transpose()?
            });

            default_fields.push(quote! {
                #field_name: None
            });
        } else {
            as_attributes_fields.push(quote! {
                owned.insert(#field_name_str.to_string(), self.#field_name.to_string());
            });

            let field_type = &field.ty;
            from_hashmap_fields.push(quote! {
                #field_name: attrs.get(#field_name_str)
                    .ok_or(::oo7::SchemaError::MissingField(#field_name_str))?
                    .parse::<#field_type>()
                    .map_err(|_| ::oo7::SchemaError::InvalidValue {
                        field: #field_name_str,
                        value: attrs.get(#field_name_str).unwrap().to_string(),
                    })?
            });

            default_fields.push(quote! {
                #field_name: Default::default()
            });
        }
    }

    let schema_name_const = quote! {
        impl #name {
            pub const SCHEMA_NAME: &'static str = #schema_name;
        }
    };

    let search_attributes_override = if dont_match_name {
        quote! {
            fn search_attributes(&self) -> ::std::collections::HashMap<String, String> {
                let mut attrs = self.as_attributes();
                attrs.remove(::oo7::XDG_SCHEMA_ATTRIBUTE);
                attrs
            }
        }
    } else {
        quote! {}
    };

    let as_attributes_impl = quote! {
        impl ::oo7::AsAttributes for #name {
            fn as_attributes(&self) -> ::std::collections::HashMap<String, String> {
                let mut owned = ::std::collections::HashMap::new();
                owned.insert(::oo7::XDG_SCHEMA_ATTRIBUTE.to_string(), Self::SCHEMA_NAME.to_string());
                #(#as_attributes_fields)*
                owned
            }

            #search_attributes_override
        }
    };

    let verify_schema = quote! {
        if let Some(schema) = attrs.get(::oo7::XDG_SCHEMA_ATTRIBUTE) {
            let schema_str: &str = schema.as_ref();
            if schema_str != Self::SCHEMA_NAME {
                return Err(::oo7::SchemaError::SchemaMismatch {
                    expected: Self::SCHEMA_NAME.to_string(),
                    found: schema_str.to_string(),
                });
            }
        }
    };

    let try_from_impl = quote! {
        impl ::std::convert::TryFrom<::std::collections::HashMap<String, String>> for #name {
            type Error = ::oo7::SchemaError;

            fn try_from(attrs: ::std::collections::HashMap<String, String>) -> ::std::result::Result<Self, Self::Error> {
                #verify_schema

                Ok(Self {
                    #(#from_hashmap_fields,)*
                })
            }
        }

        impl ::std::convert::TryFrom<&::std::collections::HashMap<String, String>> for #name {
            type Error = ::oo7::SchemaError;

            fn try_from(attrs: &::std::collections::HashMap<String, String>) -> ::std::result::Result<Self, Self::Error> {
                #verify_schema

                Ok(Self {
                    #(#from_hashmap_fields,)*
                })
            }
        }
    };

    let expanded = quote! {
        #schema_name_const
        #as_attributes_impl
        #try_from_impl
    };

    TokenStream::from(expanded)
}

/// Extract the schema config from #[schema(name = "...", dont_match_name)]
/// attribute
fn extract_schema_config(attrs: &[syn::Attribute]) -> Option<(String, bool)> {
    for attr in attrs {
        if attr.path().is_ident("schema")
            && let Meta::List(meta_list) = &attr.meta
        {
            let nested = meta_list
                .parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )
                .ok()?;

            let mut name = None;
            let mut dont_match_name = false;

            for meta in &nested {
                match meta {
                    Meta::NameValue(nv)
                        if nv.path.is_ident("name")
                            && let syn::Expr::Lit(expr_lit) = &nv.value
                            && let Lit::Str(lit_str) = &expr_lit.lit =>
                    {
                        name = Some(lit_str.value());
                    }
                    Meta::Path(path) if path.is_ident("dont_match_name") => {
                        dont_match_name = true;
                    }
                    _ => {}
                }
            }

            return name.map(|n| (n, dont_match_name));
        }
    }
    None
}

/// Check if a type is Option<T>
fn is_option_type(ty: &Type) -> bool {
    if let Type::Path(TypePath { path, .. }) = ty
        && let Some(segment) = path.segments.last()
    {
        return segment.ident == "Option";
    }
    false
}

/// Extract the inner type T from Option<T>
///
/// # Panics
///
/// This function should only be called after verifying the type is Option<T>
/// with is_option_type(). If called with a non-Option type, it will cause a
/// compile error in the generated code.
fn extract_option_inner_type(ty: &Type) -> &Type {
    if let Type::Path(TypePath { path, .. }) = ty
        && let Some(segment) = path.segments.last()
        && segment.ident == "Option"
        && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
        && let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first()
    {
        return inner_ty;
    }
    // This should never be reached if is_option_type() returned true
    // Return the original type as a fallback - this will cause a compile error
    // later
    ty
}
