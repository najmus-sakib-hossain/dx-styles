use libc::{c_int, c_ulong, winsize, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
use std::mem::zeroed;

#[cfg(any(target_os = "linux", target_os = "android"))]
static TIOCGWINSZ: c_ulong = 0x5413;

#[cfg(any(target_os = "macos",
          target_os = "ios",
          target_os = "dragonfly",
          target_os = "freebsd",
          target_os = "netbsd",
          target_os = "openbsd"))]
static TIOCGWINSZ: c_ulong = 0x40087468;

#[cfg(target_os = "solaris")]
static TIOCGWINSZ: c_ulong = 0x5468;

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

unsafe fn get_dimensions_any() -> winsize {
    unsafe {
        let mut window: winsize = zeroed();
        let mut result = ioctl(STDOUT_FILENO, TIOCGWINSZ, &mut window);

        if result == -1 {
            window = zeroed();
            result = ioctl(STDIN_FILENO, TIOCGWINSZ, &mut window);
            if result == -1 {
                window = zeroed();
                result = ioctl(STDERR_FILENO, TIOCGWINSZ, &mut window);
                if result == -1 {
                    return zeroed();
                }
            }
        }
        window
    }
}

unsafe fn get_dimensions_out() -> winsize {
    unsafe {
        let mut window: winsize = zeroed();
        let result = ioctl(STDOUT_FILENO, TIOCGWINSZ, &mut window);

        if result != -1 {
            return window;
        }
        zeroed()
    }
}

unsafe fn get_dimensions_in() -> winsize {
    unsafe {
        let mut window: winsize = zeroed();
        let result = ioctl(STDIN_FILENO, TIOCGWINSZ, &mut window);

        if result != -1 {
            return window;
        }
        zeroed()
    }
}

unsafe fn get_dimensions_err() -> winsize {
    unsafe {
        let mut window: winsize = zeroed();
        let result = ioctl(STDERR_FILENO, TIOCGWINSZ, &mut window);

        if result != -1 {
            return window;
        }
        zeroed()
    }
}

pub fn dimensions() -> Option<(usize, usize)> {
    let w = unsafe { get_dimensions_any() };

    if w.ws_col == 0 || w.ws_row == 0 {
        None
    } else {
        Some((w.ws_col as usize, w.ws_row as usize))
    }
}

pub fn dimensions_stdout() -> Option<(usize, usize)> {
    let w = unsafe { get_dimensions_out() };

    if w.ws_col == 0 || w.ws_row == 0 {
        None
    } else {
        Some((w.ws_col as usize, w.ws_row as usize))
    }
}

pub fn dimensions_stdin() -> Option<(usize, usize)> {
    let w = unsafe { get_dimensions_in() };

    if w.ws_col == 0 || w.ws_row == 0 {
        None
    } else {
        Some((w.ws_col as usize, w.ws_row as usize))
    }
}

pub fn dimensions_stderr() -> Option<(usize, usize)> {
    let w = unsafe { get_dimensions_err() };

    if w.ws_col == 0 || w.ws_row == 0 {
        None
    } else {
        Some((w.ws_col as usize, w.ws_row as usize))
    }
}
