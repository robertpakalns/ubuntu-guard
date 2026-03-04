#[derive(Debug, PartialEq)]
pub enum Log<'a> {
    Apache { ip: &'a str, path: &'a str },
    Nginx { ip: &'a str, path: &'a str },
    Ssh { ip: &'a str, msg: &'a str },
}

impl<'a> Log<'a> {
    pub fn ip(&self) -> &str {
        match self {
            Self::Apache { ip, .. } => ip,
            Self::Nginx { ip, .. } => ip,
            Self::Ssh { ip, .. } => ip,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Apache { path, .. } => path,
            Self::Nginx { path, .. } => path,
            Self::Ssh { msg, .. } => msg,
        }
    }
}

fn parse_access(line: &str) -> Option<(&str, &str)> {
    // IP address is the first whitespace-separated token
    let mut parts = line.splitn(2, ' ');
    let ip = parts.next()?;
    let rest = parts.next()?;

    // Find the first quoted request
    let first_quote = rest.find('"')?;
    let after_first = &rest[first_quote + 1..];

    let second_quote = after_first.find('"')?;
    let request = &after_first[..second_quote];

    // Request should be: METHOD PATH HTTP/X.Y
    let mut req_parts = request.split_whitespace();

    let _ = req_parts.next()?; // GET/POST/CONNECT etc.
    let path = req_parts.next()?;

    Some((ip, path))
}

pub fn parse_nginx(line: &str) -> Option<Log<'_>> {
    let (ip, path) = parse_access(line)?;
    Some(Log::Nginx { ip, path })
}

pub fn parse_apache(line: &str) -> Option<Log<'_>> {
    let (ip, path) = parse_access(line)?;
    Some(Log::Apache { ip, path })
}

#[cfg(test)]
mod tests_apache2_nginx {
    use super::{Log, parse_apache};

    #[test]
    fn test_parse_apache() {
        let cases = vec![
            (
                r#"123.45.67.89 - - [24/Oct/2025:09:00:16 +0000] "GET / HTTP/1.1" 301 574 "-" "Mozilla/5.0""#,
                Some(Log::Apache {
                    ip: "123.45.67.89",
                    path: "/",
                }),
            ),
            (
                r#"98.76.54.32 - - [24/Oct/2025:09:20:49 +0000] "GET /e.php HTTP/1.1" 403 439 "-" "curl/8.14.1""#,
                Some(Log::Apache {
                    ip: "98.76.54.32",
                    path: "/e.php",
                }),
            ),
            (
                r#"111.222.333.44 - - [24/Oct/2025:10:17:16 +0000] "\x16\x03\x01" 400 483 "-" "-""#,
                None,
            ),
            (
                r#"55.66.77.88 - - [24/Oct/2025:10:17:34 +0000] "-" 408 0 "-" "-""#,
                None,
            ),
            (
                r#"123.123.123.123 - - [24/Oct/2025:10:09:35 +0000] "CONNECT api.my-ip.io:443 HTTP/1.1" 301 518 "-" "Go-http-client/1.1""#,
                Some(Log::Apache {
                    ip: "123.123.123.123",
                    path: "api.my-ip.io:443",
                }),
            ),
            (
                r#"123.123.123.123 - - [25/Oct/2025:00:29:11 +0000] "GET /mail/.env.db HTTP/1.1" 301 536 "-" "Opera/8.02 (Windows NT 5.1; U; ru)""#,
                Some(Log::Apache {
                    ip: "123.123.123.123",
                    path: "/mail/.env.db",
                }),
            ),
            (
                r#"123.123.123.123 - - [25/Oct/2025:11:10:28 +0000] "GET /db/phpmyadmin/index.php?lang=en HTTP/1.1" 301 574 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36""#,
                Some(Log::Apache {
                    ip: "123.123.123.123",
                    path: "/db/phpmyadmin/index.php?lang=en",
                }),
            ),
        ];

        for (line, expected) in cases {
            let parsed = parse_apache(line);
            assert_eq!(parsed, expected, "Line that failed: {}", line);
        }
    }
}

pub fn parse_ssh(line: &str) -> Option<Log<'_>> {
    if !(line.contains("sshd")
        && (line.contains("Invalid user") || line.contains("Failed password")))
    {
        return None;
    }

    let from_pos = line.find(" from ")?;
    // Everything after " from "
    let after = &line[from_pos + 6..];

    // The IP address is the first "word" before the next space
    let ip_end = after.find(' ')?;
    let ip = &after[..ip_end];

    Some(Log::Ssh {
        ip,
        msg: "Potentially malicious attempt",
    })
}

#[cfg(test)]
mod tests_ssh {
    use super::{Log, parse_ssh};

    #[test]
    fn test_parse_ssh_lines() {
        let cases = vec![
            (
                "2026-01-01T19:05:04.778851+00:00 rob sshd[1]: Invalid user sdfrob from 127.0.0.1 port 42",
                Some(Log::Ssh {
                    ip: "127.0.0.1",
                    msg: "Potentially malicious attempt",
                }),
            ),
            (
                "2026-01-01T19:05:47.383708+00:00 rob sshd[1]: Failed password for invalid user sdfrob from 127.0.0.1 port 42 ssh2",
                Some(Log::Ssh {
                    ip: "127.0.0.1",
                    msg: "Potentially malicious attempt",
                }),
            ),
            (
                "2026-01-01T19:06:09.199880+00:00 rob sshd[1]: Failed password for rob from 127.0.0.1 port 42 ssh2",
                Some(Log::Ssh {
                    ip: "127.0.0.1",
                    msg: "Potentially malicious attempt",
                }),
            ),
            (
                "2026-01-01T00:00:00.000000+00:00 rob CRON[1]: pam_unix(cron:session): session closed for user root",
                None,
            ),
            (
                "2026-01-01T00:00:00.000000+00:00 rob sshd[1]: pam_unix(sshd:auth): check pass; user unknown",
                None,
            ),
            (
                "2026-01-01T00:00:00.000000+00:00 rob sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1)",
                None,
            ),
        ];

        for (line, expected) in cases {
            let parsed = parse_ssh(line);
            assert_eq!(parsed, expected, "Line that failed: {}", line);
        }
    }
}
