use winapi::shared::minwindef::DWORD;
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use winapi::um::wincon::GetConsoleScreenBufferInfo;
use winapi::um::wincon::{CONSOLE_SCREEN_BUFFER_INFO, COORD, SMALL_RECT};

fn get_dimensions_any() -> Option<(usize, usize)> {
    let null_coord = COORD { X: 0, Y: 0 };
    let null_smallrect = SMALL_RECT {
        Left: 0,
        Top: 0,
        Right: 0,
        Bottom: 0,
    };

    let mut console_data = CONSOLE_SCREEN_BUFFER_INFO {
        dwSize: null_coord,
        dwCursorPosition: null_coord,
        wAttributes: 0,
        srWindow: null_smallrect,
        dwMaximumWindowSize: null_coord,
    };

    if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut console_data) } != 0 ||
       unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_INPUT_HANDLE), &mut console_data) } != 0 ||
       unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &mut console_data) } != 0 {
        Some(((console_data.srWindow.Right - console_data.srWindow.Left + 1) as usize,
              (console_data.srWindow.Bottom - console_data.srWindow.Top + 1) as usize))
    } else {
        None
    }
}

fn get_dimensions(hdl: DWORD) -> Option<(usize, usize)> {
    let null_coord = COORD { X: 0, Y: 0 };
    let null_smallrect = SMALL_RECT {
        Left: 0,
        Top: 0,
        Right: 0,
        Bottom: 0,
    };

    let mut console_data = CONSOLE_SCREEN_BUFFER_INFO {
        dwSize: null_coord,
        dwCursorPosition: null_coord,
        wAttributes: 0,
        srWindow: null_smallrect,
        dwMaximumWindowSize: null_coord,
    };

    if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(hdl), &mut console_data) } != 0 {
        Some(((console_data.srWindow.Right - console_data.srWindow.Left + 1) as usize,
              (console_data.srWindow.Bottom - console_data.srWindow.Top + 1) as usize))
    } else {
        None
    }
}

pub fn dimensions() -> Option<(usize, usize)> {
    get_dimensions_any()
}

pub fn dimensions_stdout() -> Option<(usize, usize)> {
    get_dimensions(STD_OUTPUT_HANDLE)
}

pub fn dimensions_stdin() -> Option<(usize, usize)> {
    get_dimensions(STD_INPUT_HANDLE)
}

pub fn dimensions_stderr() -> Option<(usize, usize)> {
    get_dimensions(STD_ERROR_HANDLE)
}
