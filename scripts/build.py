import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, default=ROOT / 'dist')
parser.add_argument('--version', default='0.1.0')
parser.add_argument('--platform', action='append', choices=['linux/amd64', 'linux/386', 'linux/arm64', 'linux/armv7', 'windows/amd64'])
args = parser.parse_args()
if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', args.version):
    raise SystemExit('Version must be a semantic version, for example 0.1.9.')
output = args.output.resolve()
if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
    raise SystemExit('Commit or discard source changes before building a release.')
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
timestamp = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=ROOT, text=True))
date = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
toolchain = 'go' + re.search(r'^go ([0-9.]+)$', (ROOT / 'go.mod').read_text(), re.M)[1]
module = 'github.com/hinoobers/noobtunnel-agent'
flags = f'-s -w -X {module}/internal/version.Version={args.version} -X {module}/internal/version.Commit={commit} -X {module}/internal/version.BuildDate={date}'
output.mkdir(parents=True, exist_ok=True)
checksums = {}
for system, arch, arm in [('linux', 'amd64', ''), ('linux', '386', ''),
                          ('linux', 'arm64', ''), ('linux', 'arm', '7'),
                          ('windows', 'amd64', '')]:
    platform = system + '/' + arch + ('v' + arm if arm else '')
    if args.platform and platform not in args.platform:
        continue
    name = f'noobtunnel_{system}_{arch}' + (f'v{arm}' if arm else '') + ('.exe' if system == 'windows' else '')
    environment = dict(os.environ, GOOS=system, GOARCH=arch, GOARM=arm, CGO_ENABLED='0',
                       GOENV='off', GOTOOLCHAIN=toolchain, GOWORK='off', GOFLAGS='',
                       GOEXPERIMENT='', GODEBUG='', GOAMD64='v1', GO386='sse2', GOARM64='v8.0')
    subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags', flags, '-o', str(output / name),
                    './cmd/noobtunnel'], cwd=ROOT, env=environment, check=True)
    checksums[name] = hashlib.sha256((output / name).read_bytes()).hexdigest()
    print('Built ' + name, flush=True)
for name, source in {'install.sh': 'internal/install/install.sh',
                     'install.ps1': 'internal/install/install.ps1',
                     'quick.sh': 'install/quick.sh', 'quick.ps1': 'install/quick.ps1'}.items():
    (output / name).write_bytes((ROOT / source).read_bytes().replace(b'\r\n', b'\n'))
    checksums[name] = hashlib.sha256((output / name).read_bytes()).hexdigest()
release = {'repository': 'https://github.com/hinoobers/noobtunnel-agent',
           'commit': commit, 'version': args.version, 'builtAt': date, 'toolchain': toolchain, 'checksums': checksums}
(output / 'agent-release.json').write_text(json.dumps(release, indent=2) + '\n', encoding='utf-8', newline='\n')
(output / 'checksums.json').write_text(json.dumps(checksums, indent=2) + '\n', encoding='utf-8', newline='\n')
(output / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in checksums.items()), encoding='utf-8', newline='\n')
print('Release ' + commit + ' in ' + str(output))
