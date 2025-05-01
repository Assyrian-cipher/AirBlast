#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root"
    exit 1
fi

print_status "Starting AirBlast installation..."

# Update package lists
print_status "Updating package lists..."
apt update

# Install required packages
print_status "Installing required packages..."
apt install -y python3 python3-pip aircrack-ng wireless-tools

# Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install scapy

# Make scripts executable
print_status "Setting up scripts..."
chmod +x main/app/airblast.py
chmod +x main/app/restore_network.sh

# Check if wireless tools are installed
if ! command -v iwconfig &> /dev/null; then
    print_error "iwconfig not found. Please install wireless-tools package manually."
    exit 1
fi

# Check if aircrack-ng is installed
if ! command -v airodump-ng &> /dev/null; then
    print_error "airodump-ng not found. Please install aircrack-ng package manually."
    exit 1
fi

# Check if Python and pip are installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 not found. Please install Python 3 manually."
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    print_error "pip3 not found. Please install pip3 manually."
    exit 1
fi

print_success "Installation completed successfully!"
print_status "You can now run AirBlast using: sudo python3 main/app/airblast.py"
print_status "Make sure to run as root and have a wireless adapter that supports monitor mode." 