use std::{
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub struct TailReader {
    path: Arc<PathBuf>,
    file: Arc<Mutex<File>>,
    position: Arc<Mutex<u64>>,
    inode: Arc<Mutex<u64>>,
}

impl TailReader {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        let pos = metadata.len();
        let inode = metadata.ino();

        Ok(Self {
            path: Arc::new(path),
            file: Arc::new(Mutex::new(file)),
            position: Arc::new(Mutex::new(pos)),
            inode: Arc::new(Mutex::new(inode)),
        })
    }

    pub fn read_new_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let path = &*self.path;

        let mut file = self.file.lock().unwrap();
        let mut pos = self.position.lock().unwrap();
        let mut inode = self.inode.lock().unwrap();

        if let Ok(metadata) = path.metadata() {
            let current_inode = metadata.ino();
            let reopen = current_inode != *inode || metadata.len() < *pos;

            if reopen {
                match File::open(path) {
                    Ok(new_file) => {
                        *file = new_file;
                        *pos = 0;
                        *inode = current_inode;
                    }
                    Err(e) => eprintln!("Failed to reopen {:?}: {:?}", path, e),
                }
            }
        }

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
