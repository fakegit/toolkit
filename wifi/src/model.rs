use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WifiProfile {
    pub ssid: String,
    pub interface_name: String,
    pub auth_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub is_current: bool,
}
