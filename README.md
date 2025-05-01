# AirBlast

Fully automatic wireless deauthentication attack tool with automatic channel switching and network restoration capabilities.

![AirBlast Banner](https://raw.githubusercontent.com/Assyrian-cipher/AirBlast/main/assets/banner.png)


### Prerequisites

- Linux operating system
- Python 3.x
- Root privileges
- Wireless adapter that supports monitor mode

### Installation Methods

#### Method 1: Quick Setup (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/Assyrian-cipher/AirBlast.git
cd AirBlast
```

2. Run the setup script:
```bash
cd main
sudo chmod +x setup.sh
sudo ./setup.sh
```

The setup script will:
- Install all required packages
- Set up Python dependencies
- Make the scripts executable
- Verify the installation

#### Method 2: Python Package Installation

1. Clone the repository:
```bash
git clone https://github.com/Assyrian-cipher/AirBlast.git
cd AirBlast/main
```

2. Install the package:
```bash
pip3 install .
```

3. Install system dependencies:
```bash
sudo apt update
sudo apt install -y aircrack-ng wireless-tools
```

### Manual Installation

If you prefer to install manually:

1. Install required packages:
```bash
sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng wireless-tools
```

2. Install Python dependencies:
```bash
pip3 install scapy
```

3. Make the scripts executable:
```bash
chmod +x main/app/airblast.py
chmod +x main/app/restore_network.sh
```

## Usage

1. Run the script with root privileges:
```bash
sudo python3 main/app/airblast.py
```

2. Select your wireless interface from the list
3. Choose your target network from the scan results
4. Enter the number of deauth packets (0 for continuous attack)
5. Press Ctrl+C to stop the attack and restore network configuration

## Features in Detail

### Automatic Interface Selection
- Automatically detects available wireless interfaces
- No need to manually specify interface names

### Smart Channel Switching
- Automatically detects when target AP changes channels
- Maintaining continuous deauthentication attack

### Network Restoration
- Resets Network Manager Back to Original State After Quiting (ctrl+C)

## License

[LICENSE](LICENSE)  for details.

## Disclaimer

THIS IS FOR EDUCATIONAL PURPOSES ONLY USE AT YOUR OWN RESPONSIBILITY.

## Credits

- Developed by [Assyrian-cipher](https://github.com/Assyrian-cipher)
  
