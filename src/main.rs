use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Result, Watcher};
use std::{
    env,
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

fn parse_env_usize(name: &str) -> u64 {
    env::var(name)
        .expect(&format!("{name} not set"))
        .parse::<u64>()
        .expect(&format!("{name} must be an integer"))
}

#[derive(Debug, Clone)]
enum LogSource {
    Apache(String),
    Ssh(String),
}

impl LogSource {
    fn from_path(path: &str) -> Self {
        if path == "/var/log/auth.log" {
            LogSource::Ssh(path.to_string())
        } else {
            LogSource::Apache(path.to_string())
        }
    }

    fn path(&self) -> &str {
        match self {
            LogSource::Apache(p) | LogSource::Ssh(p) => p,
        }
    }

    fn prefix(&self) -> &'static str {
        match self {
            LogSource::Apache(_) => "APACHE",
            LogSource::Ssh(_) => "SSH",
        }
    }

    fn parse<'a>(&self, line: &'a str) -> Option<parse_logs::Log<'a>> {
        match self {
            LogSource::Apache(_) => parse_logs::parse_apache(line),
            LogSource::Ssh(_) => parse_logs::parse_ssh(line),
        }
    }

    fn is_bad(&self, msg: &str) -> bool {
        match self {
            LogSource::Apache(_) => test_path::is_bad_apache(msg),
            LogSource::Ssh(_) => test_path::is_bad_ssh(msg),
        }
    }
}

fn main() {
    // Test regex for Apache and SSH logs
    // ./guard test /var/log/apache2/access.log
    // ./guard test /var/log/apache2/access.log --print-all-matched
    // ./guard test /var/log/apache2/access.log --print-all-missed
    let args: Vec<String> = std::env::args().collect();
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

    let mut file_paths: Vec<String> = vec!["/var/log/auth.log".to_string()];
    // /var/log/auth.log + all paths from LOG_PATHS
    if let Ok(paths) = env::var("LOG_PATHS") {
        for p in paths.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            file_paths.push(p.to_string());
        }
    }

    let log_sources: Vec<LogSource> = file_paths.iter().map(|p| LogSource::from_path(p)).collect();

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

    for source in log_sources {
        let log_path = PathBuf::from(source.path());
        let log_file_name = log_path
            .file_name()
            .expect("Invalid log path")
            .to_string_lossy()
            .to_string();
        let log_dir = log_path
            .parent()
            .expect("Log file must have a parent directory")
            .to_path_buf();

        let tail_reader = Arc::new(
            reader::TailReader::new(log_dir.join(&log_file_name))
                .expect("Failed to initialize TailReader"),
        );

        let tr_clone = tail_reader.clone();
        let tracker_clone = tracker.clone();
        let source_clone = source.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                        for path in &event.paths {
                            if path
                                .file_name()
                                .and_then(|f| f.to_str())
                                .map(|f| f == log_file_name)
                                .unwrap_or(false)
                            {
                                for line in tr_clone.read_new_lines() {
                                    if let Some(parsed) = source_clone.parse(&line) {
                                        let mut tracker = tracker_clone.lock().unwrap();
                                        match &parsed {
                                            parse_logs::Log::Apache { ip, path } => {
                                                if tracker.is_blocked(ip) {
                                                    continue;
                                                }
                                                if source_clone.is_bad(path) {
                                                    tracker.log(&format!(
                                                        "[{}] Registering IP {}",
                                                        source_clone.prefix(),
                                                        ip
                                                    ));
                                                    tracker.register_attempt(ip);
                                                }
                                            }
                                            parse_logs::Log::Ssh { ip, msg } => {
                                                if tracker.is_blocked(ip) {
                                                    continue;
                                                }
                                                if source_clone.is_bad(msg) {
                                                    tracker.log(&format!(
                                                        "[{}] Registering IP {}",
                                                        source_clone.prefix(),
                                                        ip
                                                    ));
                                                    tracker.register_attempt(ip);
                                                }
                                            }
                                        }
                                    } else if let LogSource::Apache(_) = source_clone {
                                        tracker_clone.lock().unwrap().log(&format!(
                                            "[{}] Failed to parse line: {}",
                                            source_clone.prefix(),
                                            line
                                        ));
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
            .watch(&log_dir, RecursiveMode::NonRecursive)
            .expect("Failed to watch log directory");

        println!("Watching directory {:?}", log_dir);
        watchers.push(watcher);
    }

    std::thread::park();
}
