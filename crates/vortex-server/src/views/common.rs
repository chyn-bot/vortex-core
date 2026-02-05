//! Common view utilities and base templates

/// Base context for all pages
pub struct BaseContext {
    pub csrf_token: String,
    pub user_name: String,
    pub user_initials: String,
    pub active_page: String,
    pub is_admin: bool,
    pub is_system_admin: bool,
}

impl BaseContext {
    pub fn new(csrf_token: String) -> Self {
        Self {
            csrf_token,
            user_name: "User".to_string(),
            user_initials: "U".to_string(),
            active_page: String::new(),
            is_admin: false,
            is_system_admin: false,
        }
    }

    pub fn with_user(mut self, name: String) -> Self {
        self.user_name = name.clone();
        self.user_initials = name
            .split_whitespace()
            .filter_map(|w| w.chars().next())
            .take(2)
            .collect::<String>()
            .to_uppercase();
        self
    }

    pub fn with_active_page(mut self, page: &str) -> Self {
        self.active_page = page.to_string();
        self
    }

    pub fn with_roles(mut self, is_admin: bool, is_system_admin: bool) -> Self {
        self.is_admin = is_admin;
        self.is_system_admin = is_system_admin;
        self
    }
}

/// Dashboard stats for display
pub struct DashboardStats {
    pub total_users: u32,
    pub active_users: u32,
    pub total_companies: u32,
    pub installed_modules: u32,
    pub available_modules: u32,
    pub audit_events_24h: u32,
    pub active_sessions: u32,
}

impl Default for DashboardStats {
    fn default() -> Self {
        Self {
            total_users: 0,
            active_users: 0,
            total_companies: 0,
            installed_modules: 2,
            available_modules: 10,
            audit_events_24h: 0,
            active_sessions: 1,
        }
    }
}

/// Generate CSRF token
pub fn generate_csrf_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token: u128 = rng.r#gen();
    format!("{:032x}", token)
}
