import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

os.umask(0o077)
os.environ['PYTHONNOUSERSITE'] = '1'
key = os.environ.pop('BUNDLE_KEY', None)
if not key:
    raise RuntimeError('BUNDLE_KEY is required')
root = Path(__file__).resolve().parent
payload = (root / 'payload.fernet').read_bytes()
public_manifest = json.loads((root / 'manifest.json').read_text())
if hashlib.sha256(payload).hexdigest() != public_manifest['payload_sha256']:
    raise RuntimeError('Encrypted payload checksum mismatch')
with tempfile.TemporaryDirectory(prefix='encrypted-job-', dir='/tmp') as directory:
    destination = Path(directory)
    deps = destination / 'dependencies'
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
                    '--no-cache-dir', '--only-binary=:all:', '--target', str(deps),
                    'cryptography==46.0.5'], check=True)
    sys.path.insert(0, str(deps))
    from cryptography.fernet import Fernet
    plaintext = Fernet(key.encode()).decrypt(payload)
    del key
    source = destination / 'source'
    source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode='r:gz') as archive:
        options = {'filter': 'data'} if sys.version_info >= (3, 12) else {}
        archive.extractall(source, **options)
    del plaintext
    manifest = json.loads((source / 'bundle_manifest.json').read_text())
    if manifest['bundle_id'] != public_manifest['bundle_id']:
        raise RuntimeError('Bundle id mismatch')
    if manifest['source_commit'] != public_manifest['source_commit']:
        raise RuntimeError('Source commit mismatch')
    print('BUNDLE_AUTHENTICATED=' + manifest['bundle_id'], flush=True)
    print('SOURCE_COMMIT=' + manifest['source_commit'], flush=True)
    if sys.argv[1:] != ['--verify-only']:
        os.environ['BUNDLE_ID'] = manifest['bundle_id']
        code = subprocess.call(manifest['entry'] + sys.argv[1:], cwd=source)
        print(f'BOOTSTRAP_EXIT={code}', flush=True)
        raise SystemExit(code)
