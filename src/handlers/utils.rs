pub(crate) fn should_ignore_path(path: &str) -> bool {
    path.starts_with("/proc/")
        || path.starts_with("/sys/")
        || path.starts_with("/dev/")
        || path.contains("/ld.so")
        || path.contains("ld-linux")
        || path == "/etc/ld.so.cache"
        || (is_lib_dir(path) && (path.ends_with(".so") || path.contains(".so.")))
}

pub(crate) fn is_lib_dir(path: &str) -> bool {
    path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/lib64/")
        || path.starts_with("/nix/store/")
}

#[cfg(test)]
mod tests {
    use super::*;

    // should_ignore_path tests

    #[test]
    fn ignore_proc_sys_dev() {
        assert!(should_ignore_path("/proc/self/maps"));
        assert!(should_ignore_path("/sys/class/net"));
        assert!(should_ignore_path("/dev/null"));
    }

    #[test]
    fn ignore_ld_so_cache() {
        assert!(should_ignore_path("/etc/ld.so.cache"));
    }

    #[test]
    fn ignore_shared_libs() {
        assert!(should_ignore_path("/usr/lib/libc.so.6"));
        assert!(should_ignore_path("/lib/x86_64-linux-gnu/libm.so"));
        assert!(should_ignore_path("/nix/store/abc123/lib.so.3"));
    }

    #[test]
    fn do_not_ignore_user_files() {
        assert!(!should_ignore_path("/home/user/data.txt"));
        assert!(!should_ignore_path("/etc/hosts"));
        assert!(!should_ignore_path("/tmp/output.log"));
    }

    #[test]
    fn ignore_ld_linux() {
        assert!(should_ignore_path("/lib64/ld-linux-x86-64.so.2"));
    }

    // is_lib_dir tests

    #[test]
    fn lib_dirs_recognized() {
        assert!(is_lib_dir("/lib/something"));
        assert!(is_lib_dir("/lib64/something"));
        assert!(is_lib_dir("/usr/lib/something"));
        assert!(is_lib_dir("/usr/lib64/something"));
        assert!(is_lib_dir("/nix/store/abc/something"));
    }

    #[test]
    fn non_lib_dirs() {
        assert!(!is_lib_dir("/home/user/lib.so"));
        assert!(!is_lib_dir("/etc/config"));
        assert!(!is_lib_dir("/opt/app/lib.so"));
    }

    #[test]
    fn libfoo_not_lib_dir() {
        assert!(!is_lib_dir("/libfoo/bar"));
    }
}
