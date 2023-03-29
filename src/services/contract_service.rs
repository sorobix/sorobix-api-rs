// use std::{env, io, path::PathBuf};

// pub fn get_to_root_dir(path_from_root_dir: &str) -> io::Result<PathBuf> {
//     let mut dir: PathBuf = env::current_exe()?;
//     dir.pop();
//     dir.pop();
//     dir.pop();
//     dir.push(path_from_root_dir);
//     Ok(dir)
// }

use std::env;
use std::io;
use std::path::PathBuf;

pub fn get_to_root_dir(path_from_root_dir: &str) -> io::Result<PathBuf> {
    let mut dir: PathBuf = env::current_exe()?;
    loop {
        if let Some(parent) = dir.parent() {
            if let Some(name) = parent.file_name() {
                if name == "sorobix-api-rs" {
                    dir.pop();
                    break;
                }
            }
            dir.pop();
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Could not find sorobix-api-rs directory",
            ));
        }
    }
    dir.push(path_from_root_dir);
    Ok(dir)
}

pub fn fetch_error_string_during_deployment(input_string: &str) -> &str {
    match input_string.find("\nerror: ") {
        Some(index) => &input_string[index + "\nerror: ".len()..],
        None => "",
    }
}
