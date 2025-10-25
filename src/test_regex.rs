use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use crate::{LogSource, parse_logs};

pub fn test(path: &str, print_matched: bool, print_missed: bool) {
    let source = LogSource::from_path(path);
    let file = File::open(path).expect(&format!("Failed to open {path}"));
    let reader = BufReader::new(file);

    println!("Testing regex for {path}\n");

    let mut total_lines = 0;
    let mut matched_lines = 0;
    let mut unmatched_lines = 0;
    let mut failed_parse_lines = 0;

    for line in reader.lines().flatten() {
        total_lines += 1;
        let mut matched = false;
        let mut parsed_ok = false;

        if let Some(parsed) = source.parse(&line) {
            parsed_ok = true;
            match parsed {
                parse_logs::Log::Apache { ip: _, path } => {
                    if source.is_bad(path) {
                        matched = true;
                        matched_lines += 1;
                    } else {
                        unmatched_lines += 1;
                    }
                }
                parse_logs::Log::Ssh { ip: _, msg } => {
                    if source.is_bad(msg) {
                        matched = true;
                        matched_lines += 1;
                    } else {
                        unmatched_lines += 1;
                    }
                }
            }
        } else {
            failed_parse_lines += 1;
        }

        if matched && print_matched {
            println!("[MATCHED] {line}");
        } else if !matched && parsed_ok && print_missed {
            println!("[MISSED] {line}");
        } else if !parsed_ok && print_missed {
            println!("[FAILED TO PARSE] {line}");
        }
    }

    println!(
        "\nProcessed {total_lines}, matched {matched_lines}, missed {unmatched_lines}, failed to parse {failed_parse_lines} lines."
    );
}
