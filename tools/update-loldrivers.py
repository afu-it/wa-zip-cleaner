"""Refresh data/loldrivers.csv from LOLDrivers (https://www.loldrivers.io, Apache-2.0).

Run from the repo root: python3 tools/update-loldrivers.py
"""
import csv, io, urllib.request

SRC = 'https://www.loldrivers.io/api/drivers.csv'
rows = csv.DictReader(io.StringIO(urllib.request.urlopen(SRC, timeout=60).read().decode('utf-8')))
seen = {}
for r in rows:
    kind = 'malicious' if r['Category'].strip().lower() == 'malicious' else 'vulnerable'
    name = (r['Tags'].split(',')[0].strip() or r['Id'])[:60]
    for h in r['KnownVulnerableSamples_SHA256'].split(','):
        h = h.strip().lower()
        if len(h) == 64 and (h not in seen or kind == 'malicious'):
            seen[h] = (kind, name)
with open('data/loldrivers.csv', 'w', newline='', encoding='ascii', errors='replace') as f:
    w = csv.writer(f, lineterminator='\n')
    w.writerow(['sha256', 'kind', 'name'])
    for h in sorted(seen):
        w.writerow([h, *seen[h]])
print(len(seen), 'hashes,', sum(1 for v in seen.values() if v[0] == 'malicious'), 'malicious')
