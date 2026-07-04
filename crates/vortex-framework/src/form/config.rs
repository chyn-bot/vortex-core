//! Form declaration: fields, kinds, sections.

/// What a field is — determines the widget, the SQL cast, and the
/// server-side validation applied to submitted values.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    /// Single-line text (`<input type="text">`), TEXT/VARCHAR column.
    Text,
    /// Multi-line text (`<textarea>`), TEXT column.
    TextArea,
    /// Decimal/integer (`<input type="number">`), cast `::numeric`.
    Number,
    /// Date (`<input type="date">`), cast `::date`.
    Date,
    /// Date+time (`<input type="datetime-local">`), cast `::timestamptz`.
    DateTime,
    /// Boolean (`<input type="checkbox">`), cast `::boolean`.
    Checkbox,
    /// Fixed choice list (`<select>`); submitted value must be one of
    /// the declared option codes.
    Select(Vec<(String, String)>),
    /// Reference to another record (`<select>` over the related
    /// table), cast `::uuid`. Options load at render time as
    /// `SELECT id, <display> FROM <table> WHERE active IS NOT FALSE`.
    Many2One {
        table: String,
        /// Display column, default `name`.
        display: String,
    },
}

/// One form field. Construct via the kind-specific constructors, then
/// chain modifiers.
#[derive(Debug, Clone)]
pub struct FormField {
    pub name: String,
    pub label: String,
    pub kind: FieldKind,
    pub required: bool,
    pub readonly: bool,
    pub placeholder: Option<String>,
    pub help: Option<String>,
    /// Default value used in Create mode when no value is present.
    pub default: Option<String>,
}

impl FormField {
    fn new(name: &str, label: &str, kind: FieldKind) -> Self {
        Self {
            name: name.to_string(),
            label: label.to_string(),
            kind,
            required: false,
            readonly: false,
            placeholder: None,
            help: None,
            default: None,
        }
    }

    pub fn text(name: &str, label: &str) -> Self {
        Self::new(name, label, FieldKind::Text)
    }
    pub fn textarea(name: &str, label: &str) -> Self {
        Self::new(name, label, FieldKind::TextArea)
    }
    pub fn number(name: &str, label: &str) -> Self {
        Self::new(name, label, FieldKind::Number)
    }
    pub fn date(name: &str, label: &str) -> Self {
        Self::new(name, label, FieldKind::Date)
    }
    pub fn datetime(name: &str, label: &str) -> Self {
        Self::new(name, label, FieldKind::DateTime)
    }
    pub fn checkbox(name: &str, label: &str) -> Self {
        Self::new(name, label, FieldKind::Checkbox)
    }
    pub fn select(name: &str, label: &str, options: &[(&str, &str)]) -> Self {
        Self::new(
            name,
            label,
            FieldKind::Select(
                options.iter().map(|(v, l)| (v.to_string(), l.to_string())).collect(),
            ),
        )
    }
    /// Reference field over `table` (display column `name`; override
    /// with [`FormField::display`]).
    pub fn many2one(name: &str, label: &str, table: &str) -> Self {
        Self::new(
            name,
            label,
            FieldKind::Many2One { table: table.to_string(), display: "name".to_string() },
        )
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub fn readonly(mut self) -> Self {
        self.readonly = true;
        self
    }
    pub fn placeholder(mut self, p: &str) -> Self {
        self.placeholder = Some(p.to_string());
        self
    }
    pub fn help(mut self, h: &str) -> Self {
        self.help = Some(h.to_string());
        self
    }
    pub fn default(mut self, v: &str) -> Self {
        self.default = Some(v.to_string());
        self
    }
    /// Override the display column of a [`FieldKind::Many2One`].
    pub fn display(mut self, column: &str) -> Self {
        if let FieldKind::Many2One { display, .. } = &mut self.kind {
            *display = column.to_string();
        }
        self
    }
}

/// A titled group of fields, rendered as a card section.
#[derive(Debug, Clone)]
pub struct FormSection {
    pub title: Option<String>,
    pub fields: Vec<FormField>,
}

/// The form declaration: what it edits, where it submits, its fields.
#[derive(Debug, Clone)]
pub struct FormConfig {
    /// Human title ("New Parking Item" is derived per mode).
    pub title: String,
    /// Target table. Validated as an identifier before any SQL.
    pub table: String,
    /// URL base of the owning module, e.g. `/parking` — used for the
    /// cancel link and post-save redirect (`{base}/{id}`).
    pub base_url: String,
    pub sections: Vec<FormSection>,
}

impl FormConfig {
    pub fn new(title: &str, table: &str, base_url: &str) -> Self {
        Self {
            title: title.to_string(),
            table: table.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            sections: vec![FormSection { title: None, fields: Vec::new() }],
        }
    }

    /// Start a new titled section; subsequent [`FormConfig::field`]
    /// calls add to it.
    pub fn section(mut self, title: &str) -> Self {
        // Replace the initial implicit empty section instead of
        // leaving a ghost group at the top.
        if self.sections.len() == 1
            && self.sections[0].title.is_none()
            && self.sections[0].fields.is_empty()
        {
            self.sections.clear();
        }
        self.sections.push(FormSection { title: Some(title.to_string()), fields: Vec::new() });
        self
    }

    pub fn field(mut self, field: FormField) -> Self {
        self.sections.last_mut().expect("sections never empty").fields.push(field);
        self
    }

    /// Flat iterator over every field in declaration order.
    pub fn fields(&self) -> impl Iterator<Item = &FormField> {
        self.sections.iter().flat_map(|s| s.fields.iter())
    }
}
