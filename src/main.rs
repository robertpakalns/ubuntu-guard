use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Result, Watcher};
use std::{
    collections::HashMap,
    env,
    fs::read_dir,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::{sleep, spawn},
    time::Duration,
};

mod guard;
mod parse_logs;
mod reader;
mod test_path;
mod test_regex;

fn parse_env_usize(name: &str) -> u64 {
    env::var(name)
        .expect(&format!("{name} not set"))
        .parse::<u64>()
        .expect(&format!("{name} must be an integer"))
}

struct LogSource {
    kind: LogKind,
    path: PathBuf,
}

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

    fn path(&self) -> &PathBuf {
        &self.path
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
            LogKind::Ssh => test_path::is_bad_ssh(msg),
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

    let threshold = parse_env_usize("THRESHOLD");
    let window = parse_env_usize("WINDOW_SECONDS");
    let block_duration = parse_env_usize("BLOCK_DURATION_SECONDS");

    let guard_banned_ip_path =
        env::var("GUARD_BANNED_IP_PATH").expect("GUARD_BANNED_IP_PATH not set");
    let guard_log_path = env::var("GUARD_LOG_PATH").expect("GUARD_LOG_PATH not set");
    let web_server = env::var("WEB_SERVER").expect("WEB_SERVER not set");

    let dir_to_watch = match web_server.as_str() {
        "apache2" => "/var/log/apache2",
        _ => "/var/log/nginx",
    };

    let log_sources = vec![LogSource {
        kind: LogKind::Ssh,
        path: "/var/log/auth.log".into(),
    }];

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

    let mut watchers = Vec::new();
    let mut dir_map: HashMap<PathBuf, Vec<LogSource>> = HashMap::new();

    for source in log_sources {
        let dir = source
            .path()
            .parent()
            .expect("Log file must have a parent directory")
            .into();
        dir_map.entry(dir).or_default().push(source);
    }

    let apache_dir = PathBuf::from(dir_to_watch);
    if !dir_map.contains_key(&apache_dir) && apache_dir.exists() {
        dir_map.insert(apache_dir.clone(), vec![]);
    }

    for (log_dir, mut sources) in dir_map {
        if log_dir == PathBuf::from(dir_to_watch) {
            if let Ok(entries) = read_dir(&log_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.ends_with("access.log") {
                            let path_str = entry.path().to_string_lossy().to_string();
                            if !sources.iter().any(|s| *s.path() == path_str) {
                                sources.push(LogSource {
                                    kind: LogKind::Apache,
                                    path: path_str.into(),
                                });
                            }
                        }
                    }
                }
            }
        }

        let mut tail_readers: HashMap<String, reader::TailReader> = HashMap::new();
        let mut sources_map: HashMap<String, LogSource> = HashMap::new();

        for src in sources {
            let name = Path::new(src.path())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();

            let reader = reader::TailReader::new(src.path().into())
                .expect("Failed to initialize TailReader");

            tail_readers.insert(name.clone(), reader);
            sources_map.insert(name, src);
        }

        let watched_files: Vec<String> = sources_map.keys().cloned().collect();

        let tracker_clone = tracker.clone();
        let log_dir_clone = log_dir.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                        for path in &event.paths {
                            if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
                                if let Some(source) = sources_map.get(fname) {
                                    if let Some(reader) = tail_readers.get(fname) {
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
                                            } else {
                                                // Parsing error
                                                tracker.log(&format!(
                                                    "[{}] Failed to parse line: {}",
                                                    source.prefix(),
                                                    line
                                                ));
                                            }
                                        }
                                    }
                                }
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
            "Watching directory {:?} for log files {:?}",
            log_dir_clone, watched_files
        );
        watchers.push(watcher);
    }

    std::thread::park();
}
