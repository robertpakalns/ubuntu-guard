use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Result, Watcher};
use std::{
    collections::HashMap,
    env,
    fs::read_dir,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::{sleep, spawn},
    time::Duration,
};

mod guard;
mod parse_logs;
mod reader;
mod test_path;
mod test_regex;

fn parse_env<T: std::str::FromStr>(name: &str) -> T {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} not set"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be a valid value"))
}

struct LogSource {
    kind: LogKind,
    path: PathBuf,
}

#[derive(Clone, Copy)]
enum LogKind {
    Apache,
    Nginx,
    Ssh,
}

impl LogSource {
    fn from_path(path: &str) -> Self {
        let kind = if path == "/var/log/auth.log" {
            LogKind::Ssh
        } else if path.starts_with("/var/log/nginx") {
            LogKind::Nginx
        } else {
            LogKind::Apache
        };

        LogSource {
            kind,
            path: path.into(),
        }
    }

    fn prefix(&self) -> &'static str {
        match self.kind {
            LogKind::Apache => "APACHE",
            LogKind::Nginx => "NGINX",
            LogKind::Ssh => "SSH",
        }
    }

    fn parse<'a>(&self, line: &'a str) -> Option<parse_logs::Log<'a>> {
        match self.kind {
            LogKind::Apache => parse_logs::parse_apache(line),
            LogKind::Nginx => parse_logs::parse_nginx(line),
            LogKind::Ssh => parse_logs::parse_ssh(line),
        }
    }

    fn is_bad(&self, msg: &str) -> bool {
        match self.kind {
            LogKind::Apache | LogKind::Nginx => test_path::is_bad_path(msg),
            // If LogSource returns Some(Log<'_>), it is always bad attempt
            LogKind::Ssh => true,
        }
    }
}

fn main() {
    // Test regex for Apache and SSH logs
    // ./guard test /var/log/apache2/access.log
    // ./guard test /var/log/apache2/access.log --print-all-matched
    // ./guard test /var/log/apache2/access.log --print-all-missed
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "test" {
        if args.len() < 3 {
            eprintln!(
                "Usage: {} test <log_path> [--print-all-matched] [--print-all-missed]",
                args[0]
            );
            std::process::exit(1);
        }

        let log_path = &args[2];
        let print_matched = args.contains(&"--print-all-matched".to_string());
        let print_missed = args.contains(&"--print-all-missed".to_string());

        test_regex::test(log_path, print_matched, print_missed);
        return;
    }

    // Run the Guard continuously
    // ./guard
    dotenvy::dotenv().ok();

    let threshold: u64 = parse_env("THRESHOLD");
    let window: u64 = parse_env("WINDOW_SECONDS");
    let block_duration: u64 = parse_env("BLOCK_DURATION_SECONDS");

    let guard_banned_ip_path: String = parse_env("GUARD_BANNED_IP_PATH");
    let guard_log_path: String = parse_env("GUARD_LOG_PATH");

    let tracker = Arc::new(Mutex::new(guard::GuardTracker::new(
        threshold,
        Duration::from_secs(window),
        Duration::from_secs(block_duration),
        guard_banned_ip_path,
        guard_log_path,
    )));

    {
        let mut guard = tracker.lock().unwrap();
        guard.load_blocklist();
        guard.prepare_chain();
    }

    let tracker_clone = tracker.clone();
    spawn(move || {
        loop {
            {
                let mut tracker = tracker_clone.lock().unwrap();
                tracker.cleanup();
                tracker.save_blocklist();
            }
            sleep(Duration::from_secs(60));
        }
    });

    // Directories to watch
    let dirs_to_watch: Vec<(PathBuf, LogKind)> = vec![
        ("/var/log".into(), LogKind::Ssh),
        ("/var/log/apache2".into(), LogKind::Apache),
        ("/var/log/nginx".into(), LogKind::Nginx),
    ];

    let mut watchers = Vec::new();

    for (dir_path, kind) in dirs_to_watch {
        if !dir_path.exists() {
            println!("Skipping {:?}: directory does not exist", dir_path);
            continue;
        }

        // Collect relevant log files for this directory
        let mut log_sources = Vec::new();
        match kind {
            LogKind::Ssh => {
                let auth_log = dir_path.join("auth.log");
                if auth_log.exists() {
                    log_sources.push(LogSource {
                        kind,
                        path: auth_log,
                    });
                }
            }
            LogKind::Apache => {
                if let Ok(entries) = read_dir(&dir_path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Some(name) = path.file_name().and_then(|f| f.to_str()) {
                            if name.ends_with("access.log") {
                                log_sources.push(LogSource { kind, path });
                            }
                        }
                    }
                }
            }
            LogKind::Nginx => {
                if let Ok(entries) = read_dir(&dir_path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Some(name) = path.file_name().and_then(|f| f.to_str()) {
                            if name.ends_with("access.log") {
                                log_sources.push(LogSource { kind, path });
                            }
                        }
                    }
                }
            }
        }

        if log_sources.is_empty() {
            println!("No log files found in {:?}", dir_path);
            continue;
        }

        let mut tail_readers: HashMap<String, reader::TailReader> = HashMap::new();
        let mut sources_map: HashMap<String, LogSource> = HashMap::new();

        for src in log_sources {
            let name = src.path.file_name().unwrap().to_string_lossy().to_string();
            let reader =
                reader::TailReader::new(src.path.clone()).expect("Failed to initialize TailReader");
            tail_readers.insert(name.clone(), reader);
            sources_map.insert(name, src);
        }

        let watched_files: Vec<String> = sources_map.keys().cloned().collect();

        let tracker_clone = tracker.clone();
        let log_dir_clone = dir_path.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                        for path in &event.paths {
                            let fname = match path.file_name().and_then(|f| f.to_str()) {
                                Some(name) => name,
                                None => continue,
                            };

                            let source = match sources_map.get(fname) {
                                Some(src) => src,
                                None => continue,
                            };

                            let reader = match tail_readers.get(fname) {
                                Some(r) => r,
                                None => continue,
                            };

                            for line in reader.read_new_lines() {
                                let mut tracker = tracker_clone.lock().unwrap();

                                if let Some(parsed) = source.parse(&line) {
                                    let ip = parsed.ip();
                                    let msg = parsed.message();

                                    if !tracker.is_blocked(ip) && source.is_bad(msg) {
                                        tracker.log(&format!(
                                            "[{}] Registering IP {ip}",
                                            source.prefix(),
                                        ));
                                        tracker.register_attempt(ip);
                                    }
                                }
                                // else {
                                //     // Parsing error
                                //     tracker.log(&format!(
                                //         "[{}] Failed to parse line: {}",
                                //         source.prefix(),
                                //         line
                                //     ));
                                // }
                            }
                        }
                    }
                }
            },
            Config::default()
                .with_poll_interval(Duration::from_secs(1))
                .with_compare_contents(false),
        )
        .expect("Failed to create watcher");

        watcher
            .watch(&log_dir_clone, RecursiveMode::NonRecursive)
            .expect("Failed to watch log directory");

        println!(
            "Watching directory {:?} with files: {:?}",
            log_dir_clone, watched_files
        );
        watchers.push(watcher);
    }

    std::thread::park();
}
