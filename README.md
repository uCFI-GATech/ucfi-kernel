# uCFI: Documentation

## Installation

To build and install the uCFI kernel on your system, pull the uCFI kernel
repository (this one), and in the top directory, run the following commands:

    $ cp config .config
    $ make -j8
    $ sudo make modules_install install

## Usage

### Basic Tracing

1. Tell uCFI what to monitor:

    $ echo -n a.out | sudo tee /sys/kernel/debug/pt_monitor

2. Run the target program:

    $ /path/to/a.out

3. Stop tracing:

    $ echo -e "\x00" | sudo tee /sys/kernel/debug/pt_monitor

4. Check for errors:

    $ dmesg

### IP Filter Range

uCFI can be configured to trace a limited program counter range:

    $ echo -n 0x0000000000000000\|0xFFFFFFFFFFFFFFFF\|a.out | sudo tee /sys/kernel/debug/pt_monitor

### Configuring PT

uCFI can be configured using `/sys/kernel/debug/pt_conf`. Currently only
enabling and disabling return compression is supported. Note that PT
cannot be configured while the system is tracing threads.

To enable return compression:

    $ echo 0 | sudo tee /sys/kernel/debug/pt_conf

To disable return compression:

    $ echo 1 | sudo tee /sys/kernel/debug/pt_conf

## Collecting Trace Data

uCFI uses a special pseudo-filesystem so programs can consume the trace data in
real time. Reading from `/sys/kernel/debug/pt_monitor` will block until
something is being traced and then will return the PID of the root thread of
the target. As threads belonging to the target are created, the kernel will
create pseudo-files with the name `/sys/kernel/debug/pt_<pid>`.
