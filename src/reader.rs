use std::{
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::Path,
    sync::{Arc, Mutex},
};

pub struct TailReader {
    file: Arc<Mutex<File>>,
    position: Arc<Mutex<u64>>,
}

impl TailReader {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let pos = file.metadata()?.len();

        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            position: Arc::new(Mutex::new(pos)),
        })
    }

    pub fn read_new_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();

        let mut file = self.file.lock().unwrap();
        let mut pos = self.position.lock().unwrap();

        if file.seek(SeekFrom::Start(*pos)).is_ok() {
            let reader = BufReader::new(&*file);

            for line in reader.lines() {
                if let Ok(line) = line {
                    lines.push(line);
                }
            }

            *pos = file.seek(SeekFrom::End(0)).unwrap_or(*pos);
        }

        lines
    }
}
