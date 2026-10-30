pub mod backend;
pub mod model;
pub mod saml;
pub mod service;
pub mod store;
pub mod vici;

pub const SOCKET: &str = "/run/fortigate-manager/control.sock";
