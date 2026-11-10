import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, default=ROOT / 'dist')
parser.add_argument('--version', default='0.1.0')
args = parser.parse_args()
output = args.output.resolve()
if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
    raise SystemExit('Commit or discard source changes before building a release.')
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
date = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
module = 'github.com/hinoobers/noobtunnel-agent'
flags = f'-s -w -X {module}/internal/version.Version={args.version} -X {module}/internal/version.Commit={commit} -X {module}/internal/version.BuildDate={date}'
output.mkdir(parents=True, exist_ok=True)
checksums = {}
for system, arch, arm in [('linux', 'amd64', ''), ('linux', '386', ''),
                          ('linux', 'arm64', ''), ('linux', 'arm', '7'),
                          ('windows', 'amd64', '')]:
    name = f'noobtunnel_{system}_{arch}' + (f'v{arm}' if arm else '') + ('.exe' if system == 'windows' else '')
    environment = dict(os.environ, GOOS=system, GOARCH=arch, GOARM=arm, CGO_ENABLED='0')
    subprocess.run(['go', 'build', '-trimpath', '-ldflags', flags, '-o', str(output / name),
                    './cmd/noobtunnel'], cwd=ROOT, env=environment, check=True)
    checksums[name] = hashlib.sha256((output / name).read_bytes()).hexdigest()
    print('Built ' + name, flush=True)
for name, source in {'install.sh': 'internal/install/install.sh',
                     'install.ps1': 'internal/install/install.ps1',
                     'quick.sh': 'install/quick.sh', 'quick.ps1': 'install/quick.ps1'}.items():
    shutil.copyfile(ROOT / source, output / name)
    checksums[name] = hashlib.sha256((output / name).read_bytes()).hexdigest()
release = {'repository': 'https://github.com/hinoobers/noobtunnel-agent',
           'commit': commit, 'version': args.version, 'builtAt': date, 'checksums': checksums}
(output / 'agent-release.json').write_text(json.dumps(release, indent=2) + '\n', encoding='utf-8')
(output / 'checksums.json').write_text(json.dumps(checksums, indent=2) + '\n', encoding='utf-8')
(output / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in checksums.items()), encoding='utf-8')
print('Release ' + commit + ' in ' + str(output))
