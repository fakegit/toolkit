#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use std::slice;

    use anyhow::{anyhow, Context, Result};
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows::Win32::NetworkManagement::WiFi::{
        wlan_intf_opcode_current_connection, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory,
        WlanGetProfile, WlanGetProfileList, WlanOpenHandle, WlanQueryInterface,
        wlan_opcode_value_type_query_only, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
        WLAN_OPCODE_VALUE_TYPE, WLAN_PROFILE_GET_PLAINTEXT_KEY, WLAN_PROFILE_INFO_LIST,
    };

    use crate::model::WifiProfile;
    use crate::profile_xml::parse_profile_xml;

    pub struct WlanClient {
        handle: HANDLE,
    }

    impl WlanClient {
        pub fn new() -> Result<Self> {
            let mut negotiated_version = 0;
            let mut handle = HANDLE::default();

            check(unsafe {
                WlanOpenHandle(
                    2,
                    None,
                    &mut negotiated_version,
                    &mut handle,
                )
            })
            .context("failed to open WLAN client handle")?;

            Ok(Self { handle })
        }

        pub fn current_profile(&self) -> Result<Option<WifiProfile>> {
            for interface in self.interfaces()? {
                let Some(current_connection) = self.current_connection(&interface.guid)? else {
                    continue;
                };

                if !current_connection.profile_name.is_empty() {
                    return self
                        .profile(
                            &interface.guid,
                            &interface.name,
                            &current_connection.profile_name,
                            Some(&current_connection),
                        )
                        .map(Some);
                }

                for profile_name in self.profile_names(&interface.guid)? {
                    let profile = self.profile(
                        &interface.guid,
                        &interface.name,
                        &profile_name,
                        Some(&current_connection),
                    )?;
                    if profile.is_current {
                        return Ok(Some(profile));
                    }
                }
            }

            Ok(None)
        }

        pub fn list_profiles(&self) -> Result<Vec<WifiProfile>> {
            let interfaces = self.interfaces()?;
            let mut profiles = Vec::new();

            for interface in interfaces {
                let current_connection = self.current_connection(&interface.guid)?;
                for profile_name in self.profile_names(&interface.guid)? {
                    let profile = self
                        .profile(
                            &interface.guid,
                            &interface.name,
                            &profile_name,
                            current_connection.as_ref(),
                        )?;
                    profiles.push(profile);
                }
            }

            profiles.sort_by(|left, right| {
                right
                    .is_current
                    .cmp(&left.is_current)
                    .then_with(|| left.ssid.to_lowercase().cmp(&right.ssid.to_lowercase()))
            });

            Ok(profiles)
        }

        fn interfaces(&self) -> Result<Vec<Interface>> {
            let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = null_mut();
            check(unsafe { WlanEnumInterfaces(self.handle, None, &mut list_ptr) })
                .context("failed to enumerate WLAN interfaces")?;
            let _guard = WlanMemory(list_ptr.cast());

            if list_ptr.is_null() {
                return Ok(Vec::new());
            }

            let list = unsafe { &*list_ptr };
            let items = flexible_array(&list.InterfaceInfo, list.dwNumberOfItems as usize);
            Ok(items
                .iter()
                .map(|info| Interface {
                    guid: info.InterfaceGuid,
                    name: utf16_z(&info.strInterfaceDescription),
                })
                .collect())
        }

        fn current_connection(&self, guid: &GUID) -> Result<Option<CurrentConnection>> {
            let mut data_size = 0;
            let mut data_ptr: *mut c_void = null_mut();
            let mut opcode_value_type: WLAN_OPCODE_VALUE_TYPE = wlan_opcode_value_type_query_only;

            let result = unsafe {
                WlanQueryInterface(
                    self.handle,
                    guid,
                    wlan_intf_opcode_current_connection,
                    None,
                    &mut data_size,
                    &mut data_ptr,
                    Some(&mut opcode_value_type),
                )
            };

            if result != ERROR_SUCCESS.0 {
                return Ok(None);
            }

            let _guard = WlanMemory(data_ptr);
            if data_ptr.is_null() || data_size < size_of::<WLAN_CONNECTION_ATTRIBUTES>() as u32 {
                return Ok(None);
            }

            let attributes = unsafe { &*(data_ptr.cast::<WLAN_CONNECTION_ATTRIBUTES>()) };
            let profile_name = utf16_z(&attributes.strProfileName);
            let ssid = &attributes.wlanAssociationAttributes.dot11Ssid;
            let length = ssid.uSSIDLength as usize;
            let bytes = &ssid.ucSSID[..length.min(ssid.ucSSID.len())];

            Ok(Some(CurrentConnection {
                profile_name,
                ssid: String::from_utf8_lossy(bytes).into_owned(),
            }))
        }

        fn profile_names(&self, guid: &GUID) -> Result<Vec<String>> {
            let mut list_ptr: *mut WLAN_PROFILE_INFO_LIST = null_mut();
            check(unsafe { WlanGetProfileList(self.handle, guid, None, &mut list_ptr) })
                .context("failed to enumerate WLAN profiles")?;
            let _guard = WlanMemory(list_ptr.cast());

            if list_ptr.is_null() {
                return Ok(Vec::new());
            }

            let list = unsafe { &*list_ptr };
            let items = flexible_array(&list.ProfileInfo, list.dwNumberOfItems as usize);
            Ok(items
                .iter()
                .map(|info| utf16_z(&info.strProfileName))
                .filter(|name| !name.is_empty())
                .collect())
        }

        fn profile(
            &self,
            guid: &GUID,
            interface_name: &str,
            profile_name: &str,
            current_connection: Option<&CurrentConnection>,
        ) -> Result<WifiProfile> {
            let xml = self.profile_xml(guid, profile_name)?;
            let details = parse_profile_xml(&xml);
            let ssid = details.ssid.unwrap_or_else(|| profile_name.to_string());
            let is_current = current_connection.is_some_and(|connection| {
                connection.profile_name == profile_name || connection.ssid == ssid
            });

            Ok(WifiProfile {
                is_current,
                ssid,
                interface_name: interface_name.to_string(),
                auth_type: details.auth_type,
                password: details.password,
            })
        }

        fn profile_xml(&self, guid: &GUID, profile_name: &str) -> Result<String> {
            let wide_name = to_utf16_z(profile_name);
            let mut xml_ptr = PWSTR::null();
            let mut flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            let mut granted_access = 0;

            check(unsafe {
                WlanGetProfile(
                    self.handle,
                    guid,
                    PCWSTR(wide_name.as_ptr()),
                    None,
                    &mut xml_ptr,
                    Some(&mut flags),
                    Some(&mut granted_access),
                )
            })
            .with_context(|| format!("failed to read WLAN profile '{profile_name}'"))?;
            let _guard = WlanMemory(xml_ptr.0.cast());

            if xml_ptr.is_null() {
                return Err(anyhow!("WLAN profile '{profile_name}' returned empty XML"));
            }

            Ok(unsafe { pwstr_to_string(xml_ptr) })
        }
    }

    impl Drop for WlanClient {
        fn drop(&mut self) {
            unsafe {
                let _ = WlanCloseHandle(self.handle, None);
            }
        }
    }

    struct Interface {
        guid: GUID,
        name: String,
    }

    struct CurrentConnection {
        profile_name: String,
        ssid: String,
    }

    struct WlanMemory(*mut c_void);

    impl Drop for WlanMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WlanFreeMemory(self.0);
                }
            }
        }
    }

    fn check(error: u32) -> Result<()> {
        if error == ERROR_SUCCESS.0 {
            Ok(())
        } else {
            Err(anyhow!("WLAN API returned error {error}"))
        }
    }

    fn flexible_array<T>(first: &[T; 1], count: usize) -> &[T] {
        if count == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(first.as_ptr(), count) }
        }
    }

    fn utf16_z(value: &[u16]) -> String {
        let len = value.iter().position(|ch| *ch == 0).unwrap_or(value.len());
        String::from_utf16_lossy(&value[..len])
    }

    fn to_utf16_z(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    unsafe fn pwstr_to_string(value: PWSTR) -> String {
        let mut len = 0;
        while unsafe { *value.0.add(len) } != 0 {
            len += 1;
        }
        String::from_utf16_lossy(unsafe { slice::from_raw_parts(value.0, len) })
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{bail, Result};

    use crate::model::WifiProfile;

    pub struct WlanClient;

    impl WlanClient {
        pub fn new() -> Result<Self> {
            bail!("this tool only supports Windows")
        }

        pub fn current_profile(&self) -> Result<Option<WifiProfile>> {
            bail!("this tool only supports Windows")
        }

        pub fn list_profiles(&self) -> Result<Vec<WifiProfile>> {
            bail!("this tool only supports Windows")
        }
    }
}

pub use imp::WlanClient;
