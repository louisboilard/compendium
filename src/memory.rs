use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;

const AF_INET: u16 = libc::AF_INET as u16;
const AF_INET6: u16 = libc::AF_INET6 as u16;
const AF_UNIX: u16 = libc::AF_UNIX as u16;

/// Read a null-terminated string from tracee's memory
pub fn read_string(pid: Pid, addr: usize) -> Result<String> {
    let mut result = Vec::new();
    let mut current_addr = addr;

    // Read word by word (8 bytes on x86_64)
    loop {
        let word = ptrace::read(pid, current_addr as *mut _)
            .context("Failed to read from tracee memory")? as u64;

        // Check each byte for null terminator
        for i in 0..8 {
            let byte = ((word >> (i * 8)) & 0xff) as u8;
            if byte == 0 {
                return Ok(String::from_utf8_lossy(&result).into_owned());
            }
            result.push(byte);
        }

        current_addr += 8;

        // Safety limit
        if result.len() > 4096 {
            result.truncate(4096);
            return Ok(String::from_utf8_lossy(&result).into_owned() + "...");
        }
    }
}

/// Read a buffer of known size from tracee's memory
pub fn read_buffer(pid: Pid, addr: usize, len: usize) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(len);
    let mut current_addr = addr;
    let mut remaining = len;

    while remaining > 0 {
        let word = ptrace::read(pid, current_addr as *mut _)
            .context("Failed to read from tracee memory")? as u64;

        let bytes_to_read = remaining.min(8);
        for i in 0..bytes_to_read {
            let byte = ((word >> (i * 8)) & 0xff) as u8;
            result.push(byte);
        }

        current_addr += 8;
        remaining = remaining.saturating_sub(8);
    }

    Ok(result)
}

/// Read a sockaddr structure and format it
pub fn read_sockaddr(pid: Pid, addr: usize, len: usize) -> Result<String> {
    if len < 2 {
        return Ok("???".into());
    }

    let buf = read_buffer(pid, addr, len.min(128))?;

    // First 2 bytes are the address family
    let family = u16::from_ne_bytes([buf[0], buf[1]]);

    match family {
        AF_INET => {
            if buf.len() >= 8 {
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
                Ok(format!("{}:{}", ip, port))
            } else {
                Ok("AF_INET(incomplete)".into())
            }
        }
        AF_INET6 => {
            if buf.len() >= 24 {
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                // IPv6 address is bytes 8-23
                let addr_bytes: [u8; 16] = buf[8..24].try_into().unwrap();
                let ipv6 = std::net::Ipv6Addr::from(addr_bytes);
                Ok(format!("[{}]:{}", ipv6, port))
            } else {
                Ok("AF_INET6(incomplete)".into())
            }
        }
        AF_UNIX => {
            if buf.len() > 2 {
                let path = String::from_utf8_lossy(&buf[2..])
                    .trim_end_matches('\0')
                    .to_string();
                Ok(format!("unix:{}", path))
            } else {
                Ok("AF_UNIX".into())
            }
        }
        _ => Ok(format!("AF_{}(???)", family)),
    }
}

