# goSweep

goSweep is a command-line tool designed to calculate and ping all available network addresses within a specified network range.

## Usage

To use goSweep:

```bash
./goSweep 192.168.0.1/24
```

## Features

### 1. IP Range Calculation

goSweep calculates possible network addresses based on a provided subnet mask.

### 2. Ping Sweep

Using the Linux ping command, goSweep sweeps across the calculated network addresses.

### 3. Concurrency

goSweep leverages concurrency to significantly enhance the speed of network sweeps.
