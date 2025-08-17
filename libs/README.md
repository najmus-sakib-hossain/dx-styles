use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use libc::{sched_setaffinity, cpu_set_t, CPU_SET};
use memmap2::MmapMut;
use rayon::prelude::*;

const NUM_FILES: usize = 10000;
const CONTENT: &[u8] = b"initial content padded to simulate dx-check workload....................100 bytes..";
const UPDATE_CONTENT: &[u8] = b"updated content padded to simulate dx-check workload....................100 bytes..";

fn get_dir() -> PathBuf {
    let mut path = env::temp_dir();
    path.push("modules");
    path
}

fn pin_thread(core_id: usize) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let mut cpu_set: cpu_set_t = std::mem::zeroed();
            CPU_SET(core_id, &mut cpu_set);
            let result = sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &cpu_set);
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn run_in_pinned_pool<F>(benchmark_fn: F) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()> + Send,
{
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(rayon::current_num_threads())
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    pool.install(|| {
        (0..rayon::current_num_threads()).into_par_iter().for_each(|id| {
            let _ = pin_thread(id);
        });
        benchmark_fn()
    })
}

fn create_files(paths: &[PathBuf]) -> io::Result<()> {
    paths.par_iter().try_for_each(|path| {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(CONTENT)?;
        writer.flush()?;
        Ok::<(), io::Error>(())
    })
}

fn read_files(paths: &[PathBuf]) -> io::Result<()> {
    paths.par_iter().try_for_each(|path| {
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok::<(), io::Error>(())
    })
}

fn update_files_traditionally(paths: &[PathBuf]) -> io::Result<()> {
    paths.par_iter().try_for_each(|path| {
        let file = OpenOptions::new().write(true).truncate(true).open(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(UPDATE_CONTENT)?;
        writer.flush()?;
        Ok::<(), io::Error>(())
    })
}

fn update_files_smartly(paths: &[PathBuf]) -> io::Result<()> {
    paths.par_iter().try_for_each(|path| {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut mmap = unsafe { MmapMut::map_mut(&file)? };
        if mmap.len() < UPDATE_CONTENT.len() {
            file.set_len(UPDATE_CONTENT.len() as u64)?;
            mmap = unsafe { MmapMut::map_mut(&file)? };
        }
        mmap[..UPDATE_CONTENT.len()].copy_from_slice(UPDATE_CONTENT);
        Ok::<(), io::Error>(())
    })
}

fn delete_files(paths: &[PathBuf]) -> io::Result<()> {
    paths.par_iter().try_for_each(fs::remove_file)
}

fn traditional_io() -> io::Result<()> {
    let dir_path = get_dir();
    let file_paths: Vec<_> = (0..NUM_FILES).map(|i| dir_path.join(format!("file_{}.txt", i))).collect();

    let start = Instant::now();
    create_files(&file_paths)?;
    let create_time = start.elapsed().as_millis();

    let start = Instant::now();
    read_files(&file_paths)?;
    let read_time = start.elapsed().as_millis();

    let start = Instant::now();
    update_files_traditionally(&file_paths)?;
    let update_time = start.elapsed().as_millis();

    let start = Instant::now();
    delete_files(&file_paths)?;
    let delete_time = start.elapsed().as_millis();

    println!("Traditional times (ms): Create: {}, Read: {}, Update: {}, Delete: {}", create_time, read_time, update_time, delete_time);
    println!("Total: {} ms", create_time + read_time + update_time + delete_time);
    Ok(())
}

fn smart_io() -> io::Result<()> {
    let dir_path = get_dir();
    let file_paths: Vec<_> = (0..NUM_FILES).map(|i| dir_path.join(format!("file_{}.txt", i))).collect();

    let start = Instant::now();
    create_files(&file_paths)?;
    let create_time = start.elapsed().as_millis();

    let start = Instant::now();
    read_files(&file_paths)?;
    let read_time = start.elapsed().as_millis();

    let start = Instant::now();
    update_files_smartly(&file_paths)?;
    let update_time = start.elapsed().as_millis();

    let start = Instant::now();
    delete_files(&file_paths)?;
    let delete_time = start.elapsed().as_millis();

    println!("Smart times (ms): Create: {}, Read: {}, Update: {}, Delete: {}", create_time, read_time, update_time, delete_time);
    println!("Total: {} ms", create_time + read_time + update_time + delete_time);
    Ok(())
}

fn main() -> io::Result<()> {
    let dir_path = get_dir();
    fs::create_dir_all(&dir_path)?;

    println!("Running traditional_io...");
    run_in_pinned_pool(traditional_io)?;

    println!("\nRunning smart_io (mmap Update Only)...");
    run_in_pinned_pool(smart_io)?;

    fs::remove_dir_all(&dir_path)?;
    Ok(())
}