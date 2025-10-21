use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Result, Watcher};
use std::{
    env,
    path::Path,
    sync::{Arc, Mutex},
    thread::{sleep, spawn},
    time::Duration,
};

mod guard;
mod parse_logs;
mod reader;
mod test_path;

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
    dotenvy::dotenv().ok();

    let threshold = parse_env_usize("THRESHOLD");
    let window = parse_env_usize("WINDOW_SECONDS");
    let block_duration = parse_env_usize("BLOCK_DURATION_SECONDS");

    let guard_banned_ip_path =
        env::var("GUARD_BANNED_IP_PATH").expect("GUARD_BANNED_IP_PATH not set");
    let guard_log_path = env::var("GUARD_LOG_PATH").expect("GUARD_LOG_PATH not set");

    let file_paths: Vec<String> = env::var("LOG_PATHS")
        .expect("LOG_PATHS not set")
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let log_sources: Vec<LogSource> = file_paths.iter().map(|p| LogSource::from_path(p)).collect();

    let tracker = Arc::new(Mutex::new(guard::GuardTracker::new(
        threshold,
        Duration::from_secs(window),
        Duration::from_secs(block_duration),
        guard_banned_ip_path,
        guard_log_path,
    )));

    {
        tracker.lock().unwrap().load_blocklist();
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
        let path = Path::new(source.path()).to_path_buf();
        let tail_reader =
            Arc::new(reader::TailReader::new(&path).expect("Failed to initialize TailReader"));

        let reader_clone = tail_reader.clone();
        let tracker_clone = tracker.clone();
        let source_clone = source.clone();
        let s = source.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event>| match res {
                Ok(event) => {
                    if let EventKind::Modify(_) = event.kind {
                        for line in reader_clone.read_new_lines() {
                            match source_clone.parse(&line) {
                                Some(parsed) => {
                                    let mut tracker = tracker_clone.lock().unwrap();

                                    match &parsed {
                                        parse_logs::Log::Apache { ip, path } => {
                                            if tracker.is_blocked(ip) {
                                                return;
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
                                                return;
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
                                }
                                None => {
                                    if let LogSource::Apache(_) = source_clone {
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
                Err(e) => {
                    println!("Watcher error on {}: {:?}", source.path(), e);
                }
            },
            Config::default()
                .with_poll_interval(Duration::from_secs(1))
                .with_compare_contents(false),
        )
        .expect("Failed to create watcher");

        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .expect("Failed to watch log file");

        println!("Watching {}", s.path());
        watchers.push(watcher);
    }

    std::thread::park();
}
