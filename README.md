# VOSS Configurator

A comprehensive GUI tool for configuring and managing Extreme Networks VOSS switches.

## Features

- **Base Configuration Generator**: Create complete switch configurations with customizable parameters
- **Quick Configuration**: Rapidly generate basic configurations for common scenarios
- **Live Terminal**: Connect to devices via SSH or Serial and execute commands
- **Live Configuration**: Easily configure VLANs, interfaces, and other settings on connected devices
- **Batch Configuration**: Apply configuration files to devices in bulk
- **Template System**: Save and load configuration templates

## Requirements

- Python 3.11+
- Required Python packages (see `requirements.txt`)
- For serial connections: A compatible serial adapter

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/PneumaticDoggo/Voss-Configurator.git
   cd Voss-Configurator
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python configurator.py
   ```

## Usage

### Base Configuration

The Base Configuration tab allows you to create comprehensive switch configurations:

1. Fill in the basic system information (hostname, location, etc.)
2. Configure management IP settings
3. Set up ISIS SPB-M fabric parameters (optional)
4. Add and configure VLANs
5. Configure network services (SSH, NTP, etc.)
6. Set SNMP parameters
7. Generate and save the configuration

### Live Terminal

Connect to and manage switches in real-time:

1. Choose connection type (SSH or Serial)
2. Enter connection details
3. Connect to the device
4. Use the terminal to send commands or use quick command buttons

### Live Configuration

When connected to a device, quickly configure:

- VLANs and I-SIDs
- Interface settings
- System parameters
- Apply configuration templates
- Execute bulk commands

### Batch Configuration

Apply saved configuration files to devices:

1. Connect to a device in the Terminal tab
2. Select a configuration file
3. Apply the configuration to the device

## Acknowledgments

- Extreme Networks for VOSS documentation
