use roxmltree::Document;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDetails {
    pub ssid: Option<String>,
    pub auth_type: Option<String>,
    pub password: Option<String>,
}

pub fn parse_profile_xml(xml: &str) -> ProfileDetails {
    let Ok(doc) = Document::parse(xml) else {
        return ProfileDetails {
            ssid: None,
            auth_type: None,
            password: None,
        };
    };

    ProfileDetails {
        ssid: text_for(&doc, "name"),
        auth_type: text_for(&doc, "authentication"),
        password: text_for(&doc, "keyMaterial"),
    }
}

fn text_for(doc: &Document<'_>, tag_name: &str) -> Option<String> {
    doc.descendants()
        .find(|node| node.has_tag_name(tag_name))
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::parse_profile_xml;

    #[test]
    fn parses_password_and_authentication() {
        let xml = r#"
            <WLANProfile>
                <name>Office</name>
                <MSM>
                    <security>
                        <authEncryption>
                            <authentication>WPA2PSK</authentication>
                        </authEncryption>
                        <sharedKey>
                            <keyMaterial>correct horse battery staple</keyMaterial>
                        </sharedKey>
                    </security>
                </MSM>
            </WLANProfile>
        "#;

        let details = parse_profile_xml(xml);

        assert_eq!(details.ssid.as_deref(), Some("Office"));
        assert_eq!(details.auth_type.as_deref(), Some("WPA2PSK"));
        assert_eq!(
            details.password.as_deref(),
            Some("correct horse battery staple")
        );
    }

    #[test]
    fn handles_open_networks_without_key_material() {
        let xml = r#"
            <WLANProfile>
                <name>Guest</name>
                <authentication>open</authentication>
            </WLANProfile>
        "#;

        let details = parse_profile_xml(xml);

        assert_eq!(details.ssid.as_deref(), Some("Guest"));
        assert_eq!(details.auth_type.as_deref(), Some("open"));
        assert_eq!(details.password, None);
    }

    #[test]
    fn handles_invalid_xml() {
        let details = parse_profile_xml("<WLANProfile>");

        assert_eq!(details.ssid, None);
        assert_eq!(details.auth_type, None);
        assert_eq!(details.password, None);
    }
}
