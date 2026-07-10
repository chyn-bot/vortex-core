//! Vortex Macros - Procedural macros for model derivation
//!
//! Provides derive macros for the Vortex ORM.

use darling::{FromDeriveInput, FromField};
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Ident, Type};

/// Attributes for the Model derive macro
#[derive(Debug, FromDeriveInput)]
#[darling(attributes(vortex))]
struct ModelArgs {
    ident: Ident,
    data: darling::ast::Data<(), FieldArgs>,

    /// Database table name
    #[darling(default)]
    table: Option<String>,

    /// Module this model belongs to
    #[darling(default)]
    module: Option<String>,

    /// Enable multi-tenancy
    #[darling(default)]
    multi_tenant: Option<bool>,

    /// Enable soft delete
    #[darling(default)]
    soft_delete: Option<bool>,

    /// Enable audit fields
    #[darling(default)]
    audited: Option<bool>,

    /// Display name for the metadata registry (`ir_model.display_name`).
    #[darling(default)]
    label: Option<String>,

    /// Registry name (`ir_model.name`). Defaults to the table name.
    #[darling(default)]
    name: Option<String>,
}

/// Attributes for model fields
#[derive(Debug, FromField)]
#[darling(attributes(vortex))]
struct FieldArgs {
    ident: Option<Ident>,
    ty: Type,

    /// Mark as primary key
    #[darling(default)]
    primary_key: bool,

    /// Database column name
    #[darling(default)]
    column: Option<String>,

    /// Make field required
    #[darling(default)]
    required: bool,

    /// Make field unique
    #[darling(default)]
    unique: bool,

    /// Add index
    #[darling(default)]
    indexed: bool,

    /// Default value expression
    #[darling(default)]
    default: Option<String>,

    /// Mark as readonly
    #[darling(default)]
    readonly: bool,

    /// Mark as computed field
    #[darling(default)]
    computed: bool,

    /// Dependencies for computed fields
    #[darling(default)]
    depends_on: Option<String>,

    /// Reference to another model
    #[darling(default)]
    references: Option<String>,

    /// On delete behavior
    #[darling(default)]
    on_delete: Option<String>,

    /// Mark as encrypted
    #[darling(default)]
    encrypted: bool,

    /// Skip in audit log
    #[darling(default)]
    no_audit: bool,

    /// Display label for the UI / metadata registry.
    #[darling(default)]
    label: Option<String>,

    /// UI/semantic type override for the metadata registry
    /// (e.g. "monetary", "string", "text", "number").
    #[darling(default)]
    ui_type: Option<String>,

    /// Selection options (comma-separated) → a `selection` registry field.
    #[darling(default)]
    selection: Option<String>,
}

/// Derive macro for Vortex models
///
/// # Example
///
/// ```rust,ignore
/// use vortex_macros::Model;
///
/// #[derive(Model)]
/// #[vortex(table = "users", module = "core")]
/// struct User {
///     #[vortex(primary_key)]
///     id: Uuid,
///
///     #[vortex(required, unique, indexed)]
///     email: String,
///
///     #[vortex(required)]
///     name: String,
///
///     #[vortex(encrypted)]
///     password_hash: String,
///
///     #[vortex(computed, depends_on = "first_name,last_name")]
///     display_name: String,
/// }
/// ```
#[proc_macro_derive(Model, attributes(vortex))]
pub fn derive_model(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let args = match ModelArgs::from_derive_input(&input) {
        Ok(args) => args,
        Err(e) => return e.write_errors().into(),
    };

    let name = &args.ident;
    let table_name = args.table.unwrap_or_else(|| {
        // Convert CamelCase to snake_case and pluralize
        let snake = camel_to_snake(&name.to_string());
        format!("{}s", snake)
    });
    let module_name = args.module.unwrap_or_else(|| "core".to_string());
    let multi_tenant = args.multi_tenant.unwrap_or(true);
    let soft_delete = args.soft_delete.unwrap_or(true);
    let audited = args.audited.unwrap_or(true);

    let model_label_expr = match &args.label {
        Some(l) => quote! { meta.label = Some(#l.to_string()); },
        None => quote! {},
    };
    let registry_name_expr = match &args.name {
        Some(n) => quote! { meta.registry_name = Some(#n.to_string()); },
        None => quote! {},
    };

    let fields = match &args.data {
        darling::ast::Data::Struct(fields) => fields,
        _ => panic!("Model can only be derived for structs"),
    };

    // Generate field definitions
    let field_defs: Vec<_> = fields.fields.iter().map(|f| {
        let field_name = f.ident.as_ref().expect("Named fields required");
        let field_name_str = ident_to_name(field_name);
        let column_name = f.column.clone().unwrap_or_else(|| field_name_str.clone());
        let ty = &f.ty;

        let field_type = rust_type_to_field_type(ty);
        let required = f.required;
        let primary_key = f.primary_key;
        let unique = f.unique;
        let indexed = f.indexed;
        let readonly = f.readonly;
        let encrypted = f.encrypted;
        let audit = !f.no_audit;

        let default_expr = f.default.as_ref().map(|d| {
            quote! { Some(vortex_orm::field::DefaultValue::Expression(#d.to_string())) }
        }).unwrap_or_else(|| quote! { None });

        let computed = f.computed;
        let depends_on = f.depends_on.as_ref().map(|d| {
            let deps: Vec<_> = d.split(',').map(|s| s.trim().to_string()).collect();
            quote! { vec![#(#deps.to_string()),*] }
        }).unwrap_or_else(|| quote! { vec![] });

        // A `references = "model"` attribute overrides the storage type with a
        // foreign-key Reference, which the registry projects as a `many2one`.
        let reference_expr = if let Some(model) = &f.references {
            let on_delete = match f.on_delete.as_deref() {
                Some("cascade") => quote! { vortex_orm::field::OnDelete::Cascade },
                Some("set_null") | Some("setnull") => quote! { vortex_orm::field::OnDelete::SetNull },
                Some("set_default") => quote! { vortex_orm::field::OnDelete::SetDefault },
                Some("no_action") => quote! { vortex_orm::field::OnDelete::NoAction },
                _ => quote! { vortex_orm::field::OnDelete::Restrict },
            };
            quote! {
                field.field_type = vortex_orm::field::FieldType::Reference {
                    model: #model.to_string(),
                    on_delete: #on_delete,
                };
            }
        } else {
            quote! {}
        };

        let label_expr = match &f.label {
            Some(l) => quote! { field.label = Some(#l.to_string()); },
            None => quote! {},
        };
        let ui_type_expr = match &f.ui_type {
            Some(u) => quote! { field.ui_type = Some(#u.to_string()); },
            None => quote! {},
        };
        let selection_expr = match &f.selection {
            Some(s) => {
                let opts: Vec<_> = s.split(',').map(|x| x.trim().to_string()).collect();
                quote! { field.selection = vec![#(#opts.to_string()),*]; }
            }
            None => quote! {},
        };

        quote! {
            {
                let mut field = vortex_orm::field::FieldDef::new(#field_name_str, #field_type);
                field.column = Some(#column_name.to_string());
                field.required = #required;
                field.primary_key = #primary_key;
                field.unique = #unique;
                field.indexed = #indexed;
                field.readonly = #readonly;
                field.encrypted = #encrypted;
                field.audit = #audit;
                field.default = #default_expr;
                if #computed {
                    field.field_type = vortex_orm::field::FieldType::Computed;
                    field.depends_on = #depends_on;
                }
                #reference_expr
                #label_expr
                #ui_type_expr
                #selection_expr
                field
            }
        }
    }).collect();

    // Find primary key field
    let pk_field = fields.fields.iter()
        .find(|f| f.primary_key)
        .or_else(|| fields.fields.iter().find(|f| {
            f.ident.as_ref().map(|i| i.to_string()) == Some("id".to_string())
        }))
        .expect("Model must have a primary key field");
    let pk_name = pk_field.ident.as_ref().unwrap();

    // Find company_id field if exists
    let has_company_id = fields.fields.iter().any(|f| {
        f.ident.as_ref().map(|i| i.to_string()) == Some("company_id".to_string())
    });

    let company_id_impl = if has_company_id {
        quote! { Some(vortex_common::CompanyId(self.company_id)) }
    } else {
        quote! { None }
    };

    // Generate to_values implementation
    let to_values_fields: Vec<_> = fields.fields.iter().map(|f| {
        let field_name = f.ident.as_ref().unwrap();
        let field_name_str = ident_to_name(field_name);
        quote! {
            values.insert(#field_name_str.to_string(), vortex_orm::field::Field::to_field_value(&self.#field_name));
        }
    }).collect();

    // Generate from_values implementation
    let from_values_fields: Vec<_> = fields.fields.iter().map(|f| {
        let field_name = f.ident.as_ref().unwrap();
        let field_name_str = ident_to_name(field_name);
        let ty = &f.ty;
        quote! {
            #field_name: {
                let value = values.remove(#field_name_str).unwrap_or(vortex_common::FieldValue::Null);
                <#ty as vortex_orm::field::Field>::from_field_value(value)?
            }
        }
    }).collect();

    // Generate the implementation
    let expanded = quote! {
        impl vortex_orm::model::Model for #name {
            fn meta() -> &'static vortex_orm::model::ModelMeta {
                use std::sync::OnceLock;
                static META: OnceLock<vortex_orm::model::ModelMeta> = OnceLock::new();

                META.get_or_init(|| {
                    let mut meta = vortex_orm::model::ModelMeta::new(stringify!(#name), #table_name);
                    meta.module = #module_name.to_string();
                    meta.multi_tenant = #multi_tenant;
                    meta.soft_delete = #soft_delete;
                    meta.audited = #audited;
                    #model_label_expr
                    #registry_name_expr

                    #(meta.add_field(#field_defs);)*

                    meta
                })
            }

            fn pk(&self) -> vortex_common::FieldValue {
                vortex_orm::field::Field::to_field_value(&self.#pk_name)
            }

            fn company_id(&self) -> Option<vortex_common::CompanyId> {
                #company_id_impl
            }

            fn to_values(&self) -> std::collections::HashMap<String, vortex_common::FieldValue> {
                let mut values = std::collections::HashMap::new();
                #(#to_values_fields)*
                values
            }

            fn from_values(mut values: std::collections::HashMap<String, vortex_common::FieldValue>) -> vortex_common::VortexResult<Self> {
                Ok(Self {
                    #(#from_values_fields),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}

/// Field/column name for an identifier, stripping the `r#` prefix of raw
/// identifiers so a column that collides with a Rust keyword (e.g. `ref`) can
/// be modelled as `r#ref` yet still register and map to the column `ref`.
fn ident_to_name(ident: &Ident) -> String {
    let s = ident.to_string();
    s.strip_prefix("r#").map(str::to_string).unwrap_or(s)
}

/// Convert CamelCase to snake_case
fn camel_to_snake(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_lowercase().next().unwrap());
        } else {
            result.push(c);
        }
    }
    result
}

/// Convert Rust type to FieldType expression
fn rust_type_to_field_type(ty: &Type) -> proc_macro2::TokenStream {
    let ty_str = quote!(#ty).to_string().replace(' ', "");

    match ty_str.as_str() {
        "bool" => quote! { vortex_orm::field::FieldType::Boolean },
        "i32" => quote! { vortex_orm::field::FieldType::Integer },
        "i64" => quote! { vortex_orm::field::FieldType::BigInt },
        "f32" => quote! { vortex_orm::field::FieldType::Float },
        "f64" => quote! { vortex_orm::field::FieldType::Double },
        "String" => quote! { vortex_orm::field::FieldType::Text },
        "Uuid" | "uuid::Uuid" => quote! { vortex_orm::field::FieldType::Uuid },
        "DateTime<Utc>" | "chrono::DateTime<chrono::Utc>" => {
            quote! { vortex_orm::field::FieldType::Timestamp }
        }
        "serde_json::Value" => quote! { vortex_orm::field::FieldType::Json },
        "Vec<u8>" => quote! { vortex_orm::field::FieldType::Binary },
        _ if ty_str.starts_with("Option<") => {
            // Extract inner type and recurse
            quote! { <#ty as vortex_orm::field::Field>::field_type() }
        }
        _ if ty_str.starts_with("Vec<") => {
            quote! { <#ty as vortex_orm::field::Field>::field_type() }
        }
        _ => quote! { <#ty as vortex_orm::field::Field>::field_type() },
    }
}
