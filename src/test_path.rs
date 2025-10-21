pub fn is_bad_apache(path: &str) -> bool {
    path.contains(".php")
}

pub fn is_bad_ssh(path: &str) -> bool {
    path.contains("Failed password") || path.contains("Invalid user")
}
