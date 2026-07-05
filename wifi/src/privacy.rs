pub fn display_password(password: Option<&str>, reveal: bool) -> String {
    match password {
        Some(value) if reveal => value.to_string(),
        Some(value) if value.is_empty() => "<empty>".to_string(),
        Some(value) => "*".repeat(value.chars().count().max(8)),
        None => "<unavailable>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::display_password;

    #[test]
    fn masks_passwords_by_default() {
        assert_eq!(display_password(Some("secret"), false), "********");
        assert_eq!(display_password(Some("long-password"), false), "*************");
    }

    #[test]
    fn reveals_password_when_requested() {
        assert_eq!(display_password(Some("secret"), true), "secret");
    }

    #[test]
    fn handles_missing_and_empty_values() {
        assert_eq!(display_password(None, false), "<unavailable>");
        assert_eq!(display_password(Some(""), false), "<empty>");
    }
}
