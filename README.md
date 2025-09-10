# VOSS Configurator

A comprehensive GUI tool for configuring and managing Extreme Networks VOSS switches.

## Features

- **Base Configuration Generator**: Create complete switch configurations with customizable parameters
- **Quick Configuration**: Rapidly generate basic configurations for common scenarios
- **Live Terminal**: Connect to devices via SSH or Serial and execute commands
- **Live Configuration**: Easily configure VLANs, interfaces, and other settings on connected devices
- **Batch Configuration**: Apply configuration to switches in bulk
- **Batch Template Generation**: Generate base templates including vlan creation, i-sid to vlan association and interface configs. 
- **Auto detection of the default gateway for batch configs**: The Voss configurator will automatically assign the default gateway where possible, using the IP address of the switch from a loaded CSV or manual device input.
- **Template System**: Save and load configuration templates
- **Auto Update**: The program will now automatically check for available updates and apply those automatically.

## Requirements

- Python 3.11+
- Required Python packages (see `requirements.txt`)
- For serial connections: A compatible serial adapter

## Installation

1. Download the voss_configurator.zip:
   Download or clone repository
   ```
   git clone https://github.com/PneumaticDoggo/Voss-Configurator.git
   cd Voss-Configurator
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application (Windows):
   ```
   py -3.11 configurator.py
   ```
   Run the application (Linux):
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

### Batch Config

The batch config tab allows you to create the same comprehensive switch configurations as the base config but with the following additions:

**To configure snmp values,SSH settings and NTP settings across the batch configs please input the values into the relevant text input boxes in the base config tab first**

1. Either enter devices into the GUI or add them to the configurator in bulk by using predefined parameters like management IP, Device name,snmp location, spbm nick name, spbm system ID, management vlan ID
2. Preview the configs for each individual switch
3. Select and add vlans to either all switches or only selected ones 
4. Auto assign all entered vlan IDs to all switches
5. Auto gateway recognition (Input can be changed by changeing the value in the Gateway field on the Base config tab)
6. Generate single configs before generating them all simply by clicking the 'Apply to selected' button on the selected switch in the VLAN&Port Config tab


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

1. Create base or batch config
2. Connect to a device in the Terminal tab
3. Select a configuration file
4. Apply the configuration to the device

## Acknowledgments

- Extreme Networks for VOSS documentation
