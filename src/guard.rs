use std::{
    collections::{HashMap, VecDeque},
    fmt::Write as FmtWrite,
    fs::{File, OpenOptions, create_dir_all},
    io::{BufRead, BufReader, BufWriter, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn make_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    Ok(())
}

fn new_date_str() -> String {
    let now = SystemTime::now();
    let datetime = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration,
        Err(_) => return "1970-01-01 00:00:00".to_string(),
    };

    let secs = datetime.as_secs();
    let tm = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or_else(|_| time::OffsetDateTime::UNIX_EPOCH);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.year(),
        tm.month() as u8,
        tm.day(),
        tm.hour(),
        tm.minute(),
        tm.second()
    )
}

pub struct GuardTracker {
    attempts: HashMap<String, VecDeque<Instant>>,
    blocklist: HashMap<String, Instant>,
    threshold: u64,
    window: Duration,
    block_duration: Duration,
    banned_ip_path: PathBuf,
    log_path: PathBuf,
}

impl GuardTracker {
    pub fn new(
        threshold: u64,
        window: Duration,
        block_duration: Duration,
        banned_ip_path: String,
        log_path: String,
    ) -> Self {
        Self {
            attempts: HashMap::new(),
            blocklist: HashMap::new(),
            threshold,
            window,
            block_duration,
            banned_ip_path: PathBuf::from(banned_ip_path),
            log_path: PathBuf::from(log_path),
        }
    }

    pub fn is_blocked(&mut self, ip: &str) -> bool {
        if let Some(&unblock_time) = self.blocklist.get(ip) {
            if Instant::now() >= unblock_time {
                self.blocklist.remove(ip);
                self.unban_ip(ip);
                self.save_blocklist();

                false
            } else {
                true
            }
        } else {
            false
        }
    }

    pub fn register_attempt(&mut self, ip: &str) {
        let now = Instant::now();
        let queue = self.attempts.entry(ip.to_string()).or_default();

        queue.push_back(now);

        // Cleanup
        while let Some(&front) = queue.front() {
            if now.duration_since(front) > self.window {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.threshold as usize {
            self.log(&format!("[BLOCKED] IP {ip} exceeded attempt threshold"));
            self.blocklist
                .insert(ip.to_string(), now + self.block_duration);
            self.attempts.remove(ip);
            self.ban_ip(ip);
            self.save_blocklist();
        }
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();

        self.attempts.retain(|_, queue| {
            queue.retain(|&instant| now.duration_since(instant) <= self.window);
            !queue.is_empty()
        });

        let unblocked_ips: Vec<String> = self
            .blocklist
            .iter()
            .filter_map(|(ip, &unblock_time)| {
                if now >= unblock_time {
                    Some(ip.clone())
                } else {
                    None
                }
            })
            .collect();

        for ip in &unblocked_ips {
            self.blocklist.remove(ip);
            self.log(&format!("Unbanned IP {ip}"));
            self.unban_ip(ip);
        }
    }

    pub fn save_blocklist(&self) {
        if let Err(e) = make_parent_dir(&self.banned_ip_path) {
            panic!("Failed to create parent directory: {}", e);
        }

        let now = Instant::now();
        let sys_now = SystemTime::now();

        let file = File::create(&self.banned_ip_path).expect("Failed to create blocklist file");
        let mut writer = BufWriter::new(file);

        for (ip, &unblock_instant) in &self.blocklist {
            let remaining = unblock_instant.duration_since(now);
            let unblock_time = sys_now
                .checked_add(remaining)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let unblock_timestamp = unblock_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // ip=timestamp
            writeln!(writer, "{ip}={unblock_timestamp}")
                .expect("Failed to write to blocklist file");
        }
    }

    pub fn load_blocklist(&mut self) {
        if let Err(e) = make_parent_dir(&self.banned_ip_path) {
            panic!("Failed to create parent directory: {}", e);
        }

        if !&self.banned_ip_path.exists() {
            File::create(&self.banned_ip_path).expect("Failed to create blocklist file");
        }

        let file = File::open(&self.banned_ip_path).expect("Failed to open blocklist file");
        let reader = BufReader::new(file);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX_EPOCH")
            .as_secs();

        let now_instant = Instant::now();

        for line in reader.lines() {
            if let Ok(line) = line {
                if let Some((ip, timestamp_str)) = line.split_once('=') {
                    let timestamp_str = timestamp_str.trim().trim_matches('"');

                    if let Ok(unblock_ts) = timestamp_str.parse::<u64>() {
                        if unblock_ts > now {
                            let remaining = unblock_ts - now;
                            self.blocklist.insert(
                                ip.trim().to_string(),
                                now_instant + Duration::from_secs(remaining),
                            );
                        }
                    }
                }
            }
        }
    }

    pub fn log(&self, message: &str) {
        if let Err(e) = make_parent_dir(&self.log_path) {
            eprintln!("Failed to create log directory: {e}");
            return;
        }

        let file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open log file: {e}");
                return;
            }
        };

        let mut writer = BufWriter::new(file);
        let timestamp = new_date_str();

        let mut full_message = String::new();
        let _ = write!(&mut full_message, "[{timestamp}] {message}\n");

        if let Err(e) = writer.write_all(full_message.as_bytes()) {
            eprintln!("Failed to write to log file: {e}");
        }
    }

    fn ban_ip(&self, ip: &str) {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => self.run_iptables("iptables", "-I", ip),
            Ok(IpAddr::V6(_)) => self.run_iptables("ip6tables", "-I", ip),
            Err(e) => self.log(&format!("Invalid IP address '{ip}': {e}")),
        }
    }

    fn unban_ip(&self, ip: &str) {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => self.run_iptables("iptables", "-D", ip),
            Ok(IpAddr::V6(_)) => self.run_iptables("ip6tables", "-D", ip),
            Err(e) => self.log(&format!("Invalid IP address '{ip}': {e}")),
        }
    }

    fn run_iptables(&self, cmd: &str, action: &str, ip: &str) {
        let status = Command::new("sudo")
            .arg(cmd)
            .arg(action)
            .arg("ubuntu-guard")
            .arg("-s")
            .arg(ip)
            .arg("-j")
            .arg("REJECT")
            .status();

        match status {
            Ok(s) if s.success() => self.log(&format!(
                "Successfully {} IP {ip} using {cmd}",
                if action == "-I" { "banned" } else { "unbanned" },
            )),
            Ok(s) => self.log(&format!(
                "Failed to {} IP {ip}; exit code: {s}",
                if action == "-I" { "ban" } else { "unban" },
            )),
            Err(e) => self.log(&format!(
                "Error while trying to {} IP {ip}: {e}",
                if action == "-I" { "ban" } else { "unban" },
            )),
        }
    }

    pub fn prepare_chain(&self) {
        self.create_and_link_chain("iptables");
        self.create_and_link_chain("ip6tables");
    }

    fn create_and_link_chain(&self, cmd: &str) {
        let name = "ubuntu-guard";

        let chain_exists = Command::new("sudo")
            .arg(cmd)
            .arg("-L")
            .arg(name)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !chain_exists {
            self.log(&format!("Creating new chain {name} in {cmd}"));
            if let Err(e) = Command::new("sudo").arg(cmd).arg("-N").arg(name).status() {
                self.log(&format!("Failed to create chain {name} in {cmd}: {e}"));
            }
        }

        let linked = Command::new("sudo")
            .arg(cmd)
            .arg("-C")
            .arg("INPUT")
            .arg("-j")
            .arg(name)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !linked {
            self.log(&format!("Linking {name} to INPUT in {cmd}"));
            if let Err(e) = Command::new("sudo")
                .arg(cmd)
                .arg("-A")
                .arg("INPUT")
                .arg("-j")
                .arg(name)
                .status()
            {
                self.log(&format!("Failed to link {name} to INPUT in {cmd}: {e}"));
            }
        }
    }
}
