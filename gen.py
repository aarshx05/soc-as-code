import json
from random import choice, randint, randrange

hosts = [f'host{i}' for i in range(1, 21)]
processes = ['powershell.exe', 'cmd.exe', 'notepad.exe', 'python.exe']
uris = ['/index.html', '/login', '/upload.php?cmd=whoami', '/api/data']

output_file = "synthetic_test_logs_clean.jsonl"
count = 10000

with open(output_file, 'w', encoding='utf-8') as fh:
    for _ in range(count):
        t = randint(1, 3)
        if t == 1:
            # PowerShell / process logs
            log = {
                'host': choice(hosts),
                'EventID': 4688,
                'NewProcessName': choice(processes),
                'CommandLine': ' '.join(['-'.join([choice(['-nop','-w','-c']), '...'])])
            }
        elif t == 2:
            # Web requests
            log = {
                'host': choice(hosts),
                'HttpMethod': choice(['GET', 'POST']),
                'RequestUri': choice(uris),
                'UserAgent': choice(['curl/7.64', 'Mozilla/5.0', 'python-requests/2.x'])
            }
        else:
            # Random message with optional malicious signature
            msg = 'normal message'
            if randrange(20) == 0:  # ~5% malicious
                msg = 'contains MALICIOUS_SIGNATURE in payload'
            log = {
                'host': choice(hosts),
                'message': msg,
                'random_field': randint(0, 1000)
            }
        fh.write(json.dumps(log) + '\n')

print(f"Generated {count} clean JSONL logs in {output_file}")
