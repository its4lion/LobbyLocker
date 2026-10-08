pub mod catalogue;
pub mod connections;
pub mod engine;
pub mod firewall;
pub mod i18n;
pub mod icons;
pub mod inspection;
pub mod installed;
pub mod latency;
mod launcher_folders;
pub mod model;
#[cfg(target_os = "windows")]
mod readback;
pub mod store;

pub type Result<T> = std::result::Result<T, String>;
