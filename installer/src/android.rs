//! Android installer for rooted devices with Samsung Shannon modems
//!
//! This installer supports:
//! - Google Pixel 6/7/8/9 with Samsung Exynos/Shannon modems
//! - GrapheneOS, LineageOS, or other custom ROMs with root access
//!
//! Prerequisites:
//! - Device must be rooted (Magisk, KernelSU, or similar)
//! - ADB debugging must be enabled
//! - Device must be connected via USB

use std::path::Path;
use std::time::Duration;

use adb_client::{ADBDeviceExt, ADBUSBDevice};
use anyhow::{Context, Result, anyhow, bail};
use md5::compute as md5_compute;
use tokio::time::sleep;

use crate::util::echo;
use crate::{CONFIG_TOML, RAYHUNTER_DAEMON_INIT};

/// Google Pixel USB Vendor ID
const GOOGLE_USB_VENDOR_ID: u16 = 0x18D1;

/// Pixel in ADB mode Product IDs
const PIXEL_ADB_PRODUCT_IDS: &[u16] = &[
    0x4EE7, // Pixel (ADB)
    0x4EE2, // Pixel (ADB + MTP)
    0x4EE5, // Pixel (ADB + PTP)
    0xD001, // Pixel (fastboot)
];

/// Default data directory on Android
const RAYHUNTER_DATA_DIR: &str = "/data/local/tmp/rayhunter";

/// Service script location
const RAYHUNTER_SERVICE_SCRIPT: &str = "/data/local/tmp/rayhunter/start-rayhunter.sh";

pub struct AndroidArgs {
    /// Use specific USB product ID (defaults to auto-detect)
    pub product_id: Option<u16>,
}

impl Default for AndroidArgs {
    fn default() -> Self {
        Self { product_id: None }
    }
}

/// Install rayhunter on an Android device (Pixel 6+)
pub async fn install(args: AndroidArgs) -> Result<()> {
    println!("=== Rayhunter Android Installer (Pixel 6+) ===");
    println!();
    println!("Prerequisites:");
    println!("  - Device must be rooted (Magisk/KernelSU)");
    println!("  - USB debugging must be enabled");
    println!("  - Device must authorize this computer for ADB");
    println!();

    // Find and connect to the device
    echo!("Looking for Android device ... ");
    let mut adb = find_android_device(args.product_id)?;
    println!("ok");

    // Check for root access
    echo!("Checking root access ... ");
    verify_root_access(&mut adb)?;
    println!("ok");

    // Check for Shannon modem
    echo!("Checking for Samsung Shannon modem ... ");
    verify_shannon_modem(&mut adb)?;
    println!("ok");

    // Create data directory
    echo!("Creating data directory ... ");
    adb.run_command(
        &["su", "-c", &format!("mkdir -p {}", RAYHUNTER_DATA_DIR)],
        "exit code 0",
    )?;
    println!("ok");

    // Install rayhunter daemon binary
    let rayhunter_daemon_bin = include_bytes!(env!("FILE_RAYHUNTER_DAEMON"));
    adb.install_file_as_root(
        &format!("{}/rayhunter-daemon", RAYHUNTER_DATA_DIR),
        rayhunter_daemon_bin,
    )?;

    // Install config file
    let config_content = CONFIG_TOML
        .replace("#device = \"orbic\"", "device = \"pixel9\"")
        .replace(
            "qmdl_store_path = \"/data/rayhunter/qmdl\"",
            &format!("qmdl_store_path = \"{}/qmdl\"", RAYHUNTER_DATA_DIR),
        );
    adb.install_file_as_root(
        &format!("{}/config.toml", RAYHUNTER_DATA_DIR),
        config_content.as_bytes(),
    )?;

    // Create startup script
    let startup_script = generate_startup_script();
    adb.install_file_as_root(RAYHUNTER_SERVICE_SCRIPT, startup_script.as_bytes())?;
    adb.run_command(
        &[
            "su",
            "-c",
            &format!("chmod 755 {}", RAYHUNTER_SERVICE_SCRIPT),
        ],
        "exit code 0",
    )?;

    // Start the daemon
    echo!("Starting rayhunter daemon ... ");
    start_daemon(&mut adb)?;
    println!("ok");

    // Verify it's running
    sleep(Duration::from_secs(3)).await;
    echo!("Verifying rayhunter is running ... ");
    verify_running(&mut adb)?;
    println!("ok");

    println!();
    println!("=== Installation Complete ===");
    println!();
    println!("Rayhunter is now running on your Pixel!");
    println!();
    println!("To access the web interface:");
    println!("  1. Forward the port: adb forward tcp:8080 tcp:8080");
    println!("  2. Open in browser: http://localhost:8080");
    println!();
    println!("To stop rayhunter:");
    println!("  adb shell su -c 'pkill rayhunter-daemon'");
    println!();
    println!("To start rayhunter manually:");
    println!("  adb shell su -c '{}'", RAYHUNTER_SERVICE_SCRIPT);
    println!();
    println!("Note: Samsung Shannon modem support is experimental.");
    println!("Some detection heuristics may not work identically to Qualcomm devices.");

    Ok(())
}

/// Find and connect to an Android device
fn find_android_device(product_id: Option<u16>) -> Result<ADBUSBDevice> {
    // Try specified product ID first
    if let Some(pid) = product_id {
        if let Ok(device) = ADBUSBDevice::new(GOOGLE_USB_VENDOR_ID, pid) {
            return Ok(device);
        }
    }

    // Try known Pixel product IDs
    for &pid in PIXEL_ADB_PRODUCT_IDS {
        if let Ok(device) = ADBUSBDevice::new(GOOGLE_USB_VENDOR_ID, pid) {
            return Ok(device);
        }
    }

    bail!(
        "No Android device found.\n\
         \n\
         Please ensure:\n\
         1. USB debugging is enabled in Developer Options\n\
         2. The device is connected via USB\n\
         3. You have authorized this computer for ADB access on the device\n\
         \n\
         You can verify with: adb devices"
    )
}

/// Verify the device has root access
fn verify_root_access(adb: &mut ADBUSBDevice) -> Result<()> {
    let mut output = Vec::new();
    adb.shell_command(&["su", "-c", "id"], &mut output)?;
    let output_str = String::from_utf8_lossy(&output);

    if !output_str.contains("uid=0") {
        bail!(
            "Root access not available.\n\
             \n\
             Please ensure:\n\
             1. Your device is rooted (Magisk, KernelSU, etc.)\n\
             2. You have granted root access to the shell/ADB\n\
             \n\
             Output from 'su -c id': {}",
            output_str
        );
    }

    Ok(())
}

/// Verify the device has a Samsung Shannon modem
fn verify_shannon_modem(adb: &mut ADBUSBDevice) -> Result<()> {
    let mut output = Vec::new();
    adb.shell_command(&["su", "-c", "ls -la /dev/umts_dm0"], &mut output)?;
    let output_str = String::from_utf8_lossy(&output);

    if output_str.contains("No such file") || output_str.contains("Permission denied") {
        bail!(
            "Samsung Shannon modem not found at /dev/umts_dm0.\n\
             \n\
             This installer is designed for Pixel 6+ devices with Samsung Shannon modems.\n\
             Your device may have a different modem type or the diagnostic interface\n\
             may not be exposed.\n\
             \n\
             Try checking: ls -la /dev/umts_*"
        );
    }

    Ok(())
}

/// Generate the startup script for rayhunter
fn generate_startup_script() -> String {
    format!(
        r#"#!/system/bin/sh
# Rayhunter startup script for Android (Pixel 6+)
# This script must be run as root

RAYHUNTER_DIR="{data_dir}"
DAEMON="$RAYHUNTER_DIR/rayhunter-daemon"
CONFIG="$RAYHUNTER_DIR/config.toml"
LOG="$RAYHUNTER_DIR/rayhunter.log"
PID_FILE="$RAYHUNTER_DIR/rayhunter.pid"

# Check if already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Rayhunter is already running (PID: $PID)"
        exit 0
    fi
fi

# Create QMDL storage directory
mkdir -p "$RAYHUNTER_DIR/qmdl"

# Set up networking groups (Android paranoid networking)
# GIDs: 3003=inet, 3004=net_raw
export LD_LIBRARY_PATH=/system/lib64:/vendor/lib64

# Start the daemon
echo "Starting rayhunter-daemon..."
cd "$RAYHUNTER_DIR"
nohup "$DAEMON" --config "$CONFIG" > "$LOG" 2>&1 &
echo $! > "$PID_FILE"

echo "Rayhunter started (PID: $(cat $PID_FILE))"
echo "Log file: $LOG"
echo "Web interface: http://localhost:8080"
"#,
        data_dir = RAYHUNTER_DATA_DIR
    )
}

/// Start the rayhunter daemon
fn start_daemon(adb: &mut ADBUSBDevice) -> Result<()> {
    adb.run_command(&["su", "-c", RAYHUNTER_SERVICE_SCRIPT], "Rayhunter started")
        .context("Failed to start rayhunter daemon")?;
    Ok(())
}

/// Verify rayhunter is running
fn verify_running(adb: &mut ADBUSBDevice) -> Result<()> {
    let mut output = Vec::new();
    adb.shell_command(&["su", "-c", "pgrep -f rayhunter-daemon"], &mut output)?;
    let output_str = String::from_utf8_lossy(&output);

    if output_str.trim().is_empty() {
        // Check the log for errors
        let mut log_output = Vec::new();
        adb.shell_command(
            &[
                "su",
                "-c",
                &format!("tail -20 {}/rayhunter.log", RAYHUNTER_DATA_DIR),
            ],
            &mut log_output,
        )?;
        let log_str = String::from_utf8_lossy(&log_output);

        bail!(
            "Rayhunter daemon is not running.\n\
             \n\
             Last log entries:\n{}",
            log_str
        );
    }

    Ok(())
}

/// Uninstall rayhunter from the device
pub async fn uninstall() -> Result<()> {
    echo!("Looking for Android device ... ");
    let mut adb = find_android_device(None)?;
    println!("ok");

    echo!("Stopping rayhunter ... ");
    let _ = adb.run_command(&["su", "-c", "pkill -f rayhunter-daemon"], "");
    println!("ok");

    echo!("Removing files ... ");
    adb.run_command(
        &["su", "-c", &format!("rm -rf {}", RAYHUNTER_DATA_DIR)],
        "exit code 0",
    )?;
    println!("ok");

    println!("Rayhunter has been uninstalled.");
    Ok(())
}

/// Start an ADB shell with root access
pub async fn shell() -> Result<()> {
    echo!("Looking for Android device ... ");
    let mut adb = find_android_device(None)?;
    println!("ok");

    println!("Starting root shell (type 'exit' to quit)...");

    // For interactive shell, we need to use the system adb command
    std::process::Command::new("adb")
        .args(["shell", "su"])
        .status()
        .context("Failed to start adb shell")?;

    Ok(())
}

trait AndroidInstall {
    fn run_command(&mut self, command: &[&str], expected_output: &str) -> Result<()>;
    fn install_file_as_root(&mut self, dest: &str, payload: &[u8]) -> Result<()>;
}

impl AndroidInstall for ADBUSBDevice {
    /// Run an adb shell command and verify output contains expected string
    fn run_command(&mut self, command: &[&str], expected_output: &str) -> Result<()> {
        let mut buf = Vec::<u8>::new();
        let mut cmd = Vec::<&str>::new();
        cmd.extend_from_slice(command);
        cmd.extend_from_slice(&[";", "echo", "exit code $?"]);
        self.shell_command(&cmd, &mut buf)?;
        let output = String::from_utf8_lossy(&buf);

        if !expected_output.is_empty() && !output.contains(expected_output) {
            bail!("{expected_output:?} not found in: {output}");
        }
        Ok(())
    }

    /// Install a file to the device with root permissions
    fn install_file_as_root(&mut self, dest: &str, mut payload: &[u8]) -> Result<()> {
        let file_name = Path::new(dest)
            .file_name()
            .ok_or_else(|| anyhow!("{dest} does not have a file name"))?
            .to_str()
            .ok_or_else(|| anyhow!("{dest}'s file name is not UTF8"))?;

        echo!("Sending file {dest} ... ");

        // Push to temp location first (doesn't need root)
        let tmp_path = format!("/data/local/tmp/{}", file_name);
        let file_hash = md5_compute(payload);

        self.push(&mut payload, &tmp_path)?;

        // Verify hash
        let mut hash_output = Vec::new();
        self.shell_command(&["md5sum", &tmp_path], &mut hash_output)?;
        let hash_str = String::from_utf8_lossy(&hash_output);
        if !hash_str.contains(&format!("{:x}", file_hash)) {
            bail!("File hash mismatch after transfer");
        }

        // Move to final destination with root
        self.run_command(
            &["su", "-c", &format!("mv {} {}", tmp_path, dest)],
            "exit code 0",
        )?;

        // Set permissions (executable for binaries)
        if dest.contains("daemon") || dest.contains(".sh") {
            self.run_command(&["su", "-c", &format!("chmod 755 {}", dest)], "exit code 0")?;
        }

        println!("ok");
        Ok(())
    }
}
