use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, PartialEq)]
pub enum Log<'a> {
    Apache { ip: &'a str, path: &'a str },
    Ssh { ip: &'a str, msg: &'a str },
}

static BAD_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(\S+) \S+ \S+ \[.*?\] "(?:\S+) (\S+)[^"]*" \d+ \d+ "#).unwrap()
});

pub fn parse_apache(line: &str) -> Option<Log<'_>> {
    if let Some(caps) = BAD_PATH_REGEX.captures(line) {
        let ip = caps.get(1)?.as_str();
        let path = caps.get(2)?.as_str();
        Some(Log::Apache { ip, path })
    } else {
        // Malformed requests
        line.split_whitespace().next().map(|ip| Log::Apache {
            ip,
            path: "<malformed>",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Log, parse_apache};

    #[test]
    fn test_parse_apache() {
          let cases = vec![
              (
                  r#"123.45.67.89 - - [24/Oct/2025:09:00:16 +0000] "GET / HTTP/1.1" 301 574 "-" "Mozilla/5.0""#,
                  Log::Apache {
                      ip: "123.45.67.89",
                      path: "/",
                  },
              ),
              (
                  r#"98.76.54.32 - - [24/Oct/2025:09:20:49 +0000] "GET /e.php HTTP/1.1" 403 439 "-" "curl/8.14.1""#,
                  Log::Apache {
                      ip: "98.76.54.32",
                      path: "/e.php",
                  },
              ),
              (
                  r#"111.222.333.44 - - [24/Oct/2025:10:17:16 +0000] "\x16\x03\x01" 400 483 "-" "-""#,
                  Log::Apache {
                      ip: "111.222.333.44",
                      path: "<malformed>",
                  },
              ),
              (
                  r#"55.66.77.88 - - [24/Oct/2025:10:17:34 +0000] "-" 408 0 "-" "-""#,
                  Log::Apache {
                      ip: "55.66.77.88",
                      path: "<malformed>",
                  },
              ),
              (
                  r#"123.123.123.123 - - [24/Oct/2025:10:09:35 +0000] "CONNECT api.my-ip.io:443 HTTP/1.1" 301 518 "-" "Go-http-client/1.1""#,
                  Log::Apache {
                      ip: "123.123.123.123",
                      path: "api.my-ip.io:443",
                  },
              ),
              (
                  r#"123.123.123.123 - - [25/Oct/2025:00:29:11 +0000] "GET /mail/.env.db HTTP/1.1" 301 536 "-" "Opera/8.02 (Windows NT 5.1; U; ru)""#,
                  Log::Apache {
                      ip: "123.123.123.123",
                      path: "/mail/.env.db",
                  },
              ),
              (
                  r#"123.123.123.123 - - [25/Oct/2025:11:10:28 +0000] "GET /db/phpmyadmin/index.php?lang=en HTTP/1.1" 301 574 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36""#,
                  Log::Apache {
                      ip: "123.123.123.123",
                      path: "/db/phpmyadmin/index.php?lang=en",
                  },
              ),
          ];

          for (line, expected) in cases {
              let parsed = parse_apache(line)
                  .unwrap_or_else(|| panic!("Failed to parse line: {}", line));
              assert_eq!(parsed, expected, "Line that failed: {}", line);
          }
      }
}

pub fn parse_ssh(line: &str) -> Option<Log<'_>> {
    if !line.contains("sshd") {
        return None;
    }

    if line.contains("Failed password") {
        if let Some(i) = line.find(" from ") {
            let rest = &line[i + 6..];
            if let Some(space_idx) = rest.find(' ') {
                return Some(Log::Ssh {
                    ip: &rest[..space_idx],
                    msg: "Failed password",
                });
            }
        }
    }

    if line.contains("Invalid user") {
        if let Some(i) = line.find(" from ") {
            let rest = &line[i + 6..];
            if let Some(space_idx) = rest.find(' ') {
                return Some(Log::Ssh {
                    ip: &rest[..space_idx],
                    msg: "Invalid user",
                });
            }
        }
    }

    if line.contains("Connection closed by") {
        return None;
    }

    if line.contains("authentication failure") {
        return None;
    }

    None
}
