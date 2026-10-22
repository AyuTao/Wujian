use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const LIMIT: usize = 8 * 1024 * 1024;
fn drain(mut pipe: impl Read) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    pipe.by_ref()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| "读取系统命令输出失败")?;
    if output.len() > LIMIT {
        return Err("系统命令输出超出限制".into());
    }
    Ok(output)
}
/// Authorization launchers may inherit a blocked SIGCHLD mask on macOS.
/// Poll/reap with std::process::Child instead of relying on Tokio's SIGCHLD
/// listener. Pipe workers are bounded and the UI runtime remains asynchronous.
async fn execute(
    program: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    include_stderr: bool,
) -> Result<String, String> {
    execute_timed(
        program,
        args,
        input,
        include_stderr,
        Duration::from_secs(120),
    )
    .await
}
async fn execute_timed(
    program: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    include_stderr: bool,
    timeout: Duration,
) -> Result<String, String> {
    let program = PathBuf::from(program);
    let args: Vec<String> = args.iter().map(|v| v.to_string()).collect();
    let input = input.map(Vec::from);
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(&program);
        command
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("无法启动系统命令 {}：{e}", program.display()))?;
        let stdout = child.stdout.take().ok_or("无法捕获命令输出")?;
        let stderr = child.stderr.take().ok_or("无法捕获命令错误输出")?;
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        let (in_tx, in_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = out_tx.send(drain(stdout));
        });
        std::thread::spawn(move || {
            let _ = err_tx.send(drain(stderr));
        });
        let stdin = child.stdin.take();
        std::thread::spawn(move || {
            let written = (|| -> Result<(), String> {
                if let (Some(mut pipe), Some(input)) = (stdin, input) {
                    pipe.write_all(&input).map_err(|_| "规则写入系统命令失败")?;
                }
                Ok(())
            })();
            let _ = in_tx.send(written);
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if started.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err("系统操作超时；请核验规则，不能假定已解除".to_string());
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(format!("等待系统命令失败：{error}"));
                }
            }
        };
        // Descendants may retain a pipe after the immediate process exits.
        // Bound PIPE waits too, so an authorization timeout never freezes UI.
        let remaining = || timeout.saturating_sub(started.elapsed());
        let written = in_rx
            .recv_timeout(remaining())
            .map_err(|_| "系统命令输入等待超时")?;
        let stdout = out_rx
            .recv_timeout(remaining())
            .map_err(|_| "系统命令输出等待超时；请核验当前规则")??;
        let stderr = err_rx
            .recv_timeout(remaining())
            .map_err(|_| "系统命令错误输出等待超时")??;
        let status = status?;
        if !status.success() {
            return Err(format!(
                "系统操作失败：{}",
                String::from_utf8_lossy(&stderr)
                    .chars()
                    .take(900)
                    .collect::<String>()
            ));
        }
        written?;
        let mut text = String::from_utf8_lossy(&stdout).into_owned();
        if include_stderr {
            text.push_str(&String::from_utf8_lossy(&stderr));
        }
        Ok(text)
    })
    .await
    .map_err(|_| "本地命令执行任务异常")?
}
pub async fn run(program: &Path, args: &[&str], input: Option<&[u8]>) -> Result<String, String> {
    execute(program, args, input, false).await
}
pub async fn combined(program: &Path, args: &[&str]) -> Result<String, String> {
    execute(program, args, None, true).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[tokio::test]
    async fn normal_and_blocked_sigchld_children_are_reaped() {
        assert_eq!(
            run(Path::new("/usr/bin/printf"), &["ok"], None)
                .await
                .unwrap(),
            "ok"
        );
        // Python blocks SIGCHLD before exec. This reproduces the authorization
        // child's inherited signal mask without requesting admin or PF.
        let python = ["/usr/bin/python3", "/opt/homebrew/bin/python3"]
            .into_iter()
            .find(|p| Path::new(p).is_file());
        if let Some(python) = python {
            let script="import os,signal;signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGCHLD});os.execv('/usr/bin/printf',['printf','masked'])";
            assert_eq!(
                run(Path::new(python), &["-c", script], None).await.unwrap(),
                "masked"
            );
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn inherited_pipe_cannot_extend_the_deadline() {
        let started = Instant::now();
        let result = execute_timed(
            Path::new("/bin/sh"),
            &["-c", "(sleep 2) & printf x"],
            None,
            false,
            Duration::from_millis(120),
        )
        .await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn large_input_and_output_are_drained_concurrently() {
        let bytes = vec![b'a'; 256 * 1024];
        assert_eq!(
            run(Path::new("/bin/cat"), &[], Some(&bytes))
                .await
                .unwrap()
                .len(),
            bytes.len()
        );
    }
}
