use once_cell::sync::OnceCell;
use slog::{o, Drain, Logger};

static STDOUT: OnceCell<Logger> = OnceCell::new();
static STDERR: OnceCell<Logger> = OnceCell::new();

pub fn stdout() -> &'static Logger {
    STDOUT.get().unwrap_or_else(|| {
        STDOUT.set(stdout_logger()).unwrap();
        STDOUT.get().unwrap()
    })
}

pub fn stderr() -> &'static Logger {
    STDERR.get().unwrap_or_else(|| {
        STDERR.set(stderr_logger()).unwrap();
        STDERR.get().unwrap()
    })
}

fn stdout_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    Logger::root(drain, o!())
}

fn stderr_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();

    Logger::root(drain, o!())
}
