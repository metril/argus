//! Page components

pub mod dashboard;
pub mod filters;
pub mod login;
pub mod proxy;
pub mod register;
pub mod settings;
pub mod userscripts;

pub use dashboard::DashboardPage;
pub use filters::FiltersPage;
pub use login::LoginPage;
pub use proxy::ProxyPage;
pub use register::RegisterPage;
pub use settings::SettingsPage;
pub use userscripts::UserscriptsPage;
