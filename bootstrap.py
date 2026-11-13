import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import traceback

os.umask(0o077)


def main():
    key = os.environ.pop('BUNDLE_KEY')
    root = Path(__file__).resolve().parent
    payload = (root / 'payload.fernet').read_bytes()
    public_manifest = json.loads((root / 'manifest.json').read_text())
    if hashlib.sha256(payload).hexdigest() != public_manifest['payload_sha256']:
        raise RuntimeError('Encrypted payload checksum mismatch')

    with tempfile.TemporaryDirectory(prefix='kimi-sid-bootstrap-', dir='/tmp') as directory:
        destination = Path(directory)
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            deps = destination / 'dependencies'
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
                '--no-cache-dir', '--only-binary=:all:', '--target', str(deps),
                'cryptography==46.0.5',
            ], check=True)
            sys.path.insert(0, str(deps))
            from cryptography.fernet import Fernet

        plaintext = Fernet(key.encode()).decrypt(payload)
        del key
        source = destination / 'source'
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode='r:gz') as archive:
            if hasattr(tarfile, 'data_filter'):
                archive.extractall(source, filter='data')
            else:
                resolved_source = source.resolve()
                for member in archive.getmembers():
                    target = (source / member.name).resolve()
                    if target != resolved_source and resolved_source not in target.parents:
                        raise RuntimeError('Unsafe archive path')
                    if member.issym() or member.islnk():
                        raise RuntimeError('Archive links are not allowed')
                archive.extractall(source)
        del plaintext

        manifest = json.loads((source / 'bundle_manifest.json').read_text())
        if manifest['bundle_id'] != public_manifest['bundle_id']:
            raise RuntimeError('Bundle id mismatch')
        print('BUNDLE_AUTHENTICATED=' + manifest['bundle_id'], flush=True)
        if sys.argv[1:] == ['--verify-only']:
            print('BUNDLE_VERIFY_ONLY=OK', flush=True)
            return 0

        os.environ['BUNDLE_ID'] = manifest['bundle_id']
        os.environ['SOURCE_COMMIT'] = manifest['source_commit']
        return subprocess.call(manifest['entry'] + sys.argv[1:], cwd=source)


if __name__ == '__main__':
    try:
        exit_code = main()
    except Exception:
        if sys.argv[1:] == ['--verify-only']:
            raise
        run_id = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + f'-bootstrap-{os.getpid()}'
        results = Path('/home/jovyan/xandi281/kimi-recsys-mac') / run_id
        results.mkdir(parents=True, exist_ok=True)
        error_log = results / 'bootstrap-error.log'
        error_log.write_text(traceback.format_exc(), encoding='utf-8')
        print(f'BOOTSTRAP_ERROR_LOG={error_log}', flush=True)
        print('BOOTSTRAP_EXIT=1', flush=True)
        print(traceback.format_exc(), flush=True)
        exit_code = 0
    raise SystemExit(exit_code)
