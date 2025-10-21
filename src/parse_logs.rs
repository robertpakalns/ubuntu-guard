#[derive(Debug)]
pub enum Log<'a> {
    Apache { ip: &'a str, path: &'a str },
    Ssh { ip: &'a str, msg: &'a str },
}

pub fn parse_apache(line: &str) -> Option<Log<'_>> {
    let mut parts = line.splitn(2, ' ');
    let ip = parts.next()?;
    let rest = parts.next()?;

    let method_start = rest.find('"')? + 1;
    let method_end = rest[method_start..].find('"')? + method_start;
    let request = &rest[method_start..method_end];

    let mut req_parts = request.split_whitespace();
    req_parts.next()?;
    let path = req_parts.next()?;

    Some(Log::Apache { ip, path: path })
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
