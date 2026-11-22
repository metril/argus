//! Page components

pub mod blocked;
pub mod dashboard;
pub mod filters;
pub mod login;
pub mod policy;
pub mod proxy;
pub mod register;
pub mod settings;
pub mod tokens;
pub mod userscripts;

pub use blocked::BlockedPage;
pub use dashboard::DashboardPage;
pub use filters::FiltersPage;
pub use login::LoginPage;
pub use policy::PolicyPage;
pub use proxy::ProxyPage;
pub use register::RegisterPage;
pub use settings::SettingsPage;
pub use tokens::TokensPage;
pub use userscripts::UserscriptsPage;
