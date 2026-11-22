import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {'noobtunnel_linux_amd64': 'linux/amd64', 'noobtunnel_linux_386': 'linux/386',
             'noobtunnel_linux_arm64': 'linux/arm64', 'noobtunnel_linux_armv7': 'linux/armv7',
             'noobtunnel_windows_amd64.exe': 'windows/amd64'}
SCRIPTS = ('install.sh', 'install.ps1', 'quick.sh', 'quick.ps1')


def verify(artifact, manifest):
    release = json.loads(manifest.read_text(encoding='utf-8'))
    if release.get('repository') != 'https://github.com/hinoobers/noobtunnel-agent':
        raise SystemExit('Unexpected source repository.')
    commit = release.get('commit', '')
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise SystemExit('Invalid source commit.')
    current = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if current != commit:
        raise SystemExit('Check out source commit ' + commit + ' before rebuilding.')
    if artifact.name not in PLATFORMS and artifact.name not in SCRIPTS:
        raise SystemExit('Unrecognized release artifact filename.')
    expected = release.get('checksums', {}).get(artifact.name)
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit('Downloaded file does not match the release checksum.')
    with tempfile.TemporaryDirectory(prefix='noobtunnel-rebuild-') as temporary:
        command = [sys.executable, str(ROOT / 'scripts/build.py'), '--version', release['version'], '--output', temporary]
        command += ['--platform', PLATFORMS.get(artifact.name, 'linux/amd64')]
        subprocess.run(command, cwd=ROOT, check=True)
        rebuilt = hashlib.sha256((Path(temporary) / artifact.name).read_bytes()).hexdigest()
        if actual != rebuilt:
            raise SystemExit('Rebuilt source does not match the downloaded file.')
    print(f'Verified {artifact.name}: identical to source commit {commit}\nSHA-256 {actual}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Rebuild a release artifact and compare its bytes.')
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    verify(args.artifact.resolve(), args.manifest.resolve())
