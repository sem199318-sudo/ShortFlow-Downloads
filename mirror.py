"""Mirror current stable; explicit local owner prepublication of a signed candidate.

Default cron uses only the live stable feed. Local prepublication requires a fresh
owner-accepted stable-channel envelope and publishes a not-latest prerelease.

This file may be public. It contains public verification material, no application
source, private receipt, credential, signing key or production write access.
"""
import argparse
import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPOSITORY = 'sem199318-sudo/ShortFlow-Downloads'
FEED = 'https://shortflowstudio.com/updates/stable.json'
KEYS = {'shortflow-20261009': base64.b64decode('22GdepZLwBuW604YuW3YssL80TPuFXh9aYOMrp431IM=')}
VERSION = r'(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})'
BOOTSTRAP = re.compile(r'/downloads/ShortFlow-Setup-('+VERSION+r')-x64\.exe\Z')
FIELDS = {'schema','channel','platform','version','data_contract','min_version','build',
          'url','size','sha256','notes','issued_at','expires_at','key_id'}


def versions(value):
    if type(value) is not str or not re.fullmatch(VERSION, value):
        raise ValueError('Invalid version')
    result = tuple(map(int, value.split('.')))
    if max(result)>65535:
        raise ValueError('Invalid version')
    return result


def bootstrap_version(path):
    found = BOOTSTRAP.fullmatch(path)
    if found:
        versions(found[1])
        return found[1]
    return None


def alias(version):
    versions(version)
    return 'ShortFlow-Setup-'+version+'-x64.exe'


def asset_url(version, name):
    allowed = (alias(version), alias(version)+'.sha256', 'signed-manifest.json')
    if name not in allowed:
        raise ValueError('Unexpected public asset')
    return 'https://github.com/'+REPOSITORY+'/releases/download/v'+version+'/'+name


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate field')
        value[key] = item
    return value


def verify_manifest(raw, keys=KEYS, *, now=None):
    now = time.time() if now is None else now
    try:
        if type(raw) is not bytes or not 1<=len(raw)<=65536:
            raise ValueError('Invalid metadata size')
        envelope = json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid number')))
        if type(envelope) is not dict or set(envelope)!={'manifest','signature'}:
            raise ValueError('Invalid envelope')
        value = envelope['manifest']
        if type(value) is not dict or set(value)!=FIELDS:
            raise ValueError('Invalid metadata fields')
        target, minimum = versions(value['version']), versions(value['min_version'])
        if (type(value['schema']) is not int or value['schema']!=1 or
            value['channel']!='stable' or value['platform']!='windows-x64' or
            type(value['data_contract']) is not int or not 1<=value['data_contract']<=255 or
            minimum>target or type(value['size']) is not int or
            not 2<=value['size']<=1500*1024*1024 or type(value['sha256']) is not str or
            not re.fullmatch('[a-f0-9]{64}',value['sha256']) or
            type(value['build']) is not str or not re.fullmatch('[0-9]{8}',value['build']) or
            type(value['notes']) is not str or len(value['notes'])>6000 or
            any(ord(c)<32 and c not in '\n\t' for c in value['notes']) or
            type(value['issued_at']) is not int or type(value['expires_at']) is not int or
            not 0<=value['issued_at']<=now+300 or
            not value['issued_at']<value['expires_at']<=value['issued_at']+366*86400 or
            value['expires_at']<=now):
            raise ValueError('Invalid metadata values')
        datetime.strptime(value['build'], '%Y%m%d')
        expected = ('https://shortflowstudio.com/downloads/ShortFlow-Setup-'+
                    value['version']+'-'+value['build']+'-x64.exe')
        if value['url']!=expected:
            raise ValueError('Unexpected source URL')
        public = keys[value['key_id']]
        if type(public) is not bytes or len(public)!=32 or type(envelope['signature']) is not str:
            raise ValueError('Invalid verification material')
        canonical = json.dumps(value,ensure_ascii=False,sort_keys=True,
            separators=(',',':'),allow_nan=False).encode()
        signature = base64.b64decode(envelope['signature'],validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(signature,canonical)
        return value
    except Exception as error:
        raise ValueError('Signed release metadata rejected') from error


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def response(url):
    parsed = urlsplit(url)
    if (parsed.scheme!='https' or parsed.netloc not in ('shortflowstudio.com','api.github.com')
            or parsed.username or parsed.password or parsed.fragment):
        raise ValueError('Unexpected distribution endpoint')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    return opener.open(urllib.request.Request(url, headers={
        'User-Agent':'ShortFlow-Public-Distribution/1.0','Cache-Control':'no-cache',
        'Accept':'application/vnd.github+json' if parsed.netloc=='api.github.com' else '*/*'}), timeout=30)


def read_bytes(url, limit):
    with response(url) as source:
        data = source.read(limit+1)
        if source.status!=200 or len(data)>limit:
            raise ValueError('Unexpected distribution response')
        return data


class AssetRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed = urlsplit(newurl)
        if (parsed.scheme!='https' or parsed.netloc not in
                ('github.com','release-assets.githubusercontent.com') or
                parsed.username or parsed.password or parsed.fragment):
            raise ValueError('Unexpected public asset redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def read_asset(version,name,limit):
    url = asset_url(version,name)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),AssetRedirect())
    request = urllib.request.Request(url,headers={'User-Agent':'ShortFlow-Public-Distribution/1.0',
        'Cache-Control':'no-cache'})
    with opener.open(request,timeout=30) as source:
        raw = source.read(limit+1)
        if source.status!=200 or len(raw)>limit:
            raise ValueError('Unexpected public verification asset')
        return raw


def verify_file(path, manifest):
    path = regular_file(path, 1500*1024*1024)
    if path.stat().st_size!=manifest['size']:
        raise ValueError('Installer size mismatch')
    with path.open('rb') as source:
        if source.read(2)!=b'MZ':
            raise ValueError('Installer header mismatch')
        source.seek(0)
        if hashlib.file_digest(source,'sha256').hexdigest()!=manifest['sha256']:
            raise ValueError('Installer digest mismatch')


def asset_contents(manifest, raw):
    return {alias(manifest['version'])+'.sha256':
        (manifest['sha256']+'  '+alias(manifest['version'])+'\n').encode('ascii'),
        'signed-manifest.json':raw}


def write_verification_assets(directory,manifest,raw):
    for name,body in asset_contents(manifest,raw).items():
        (Path(directory)/name).write_bytes(body)


def match_release(release, manifest, raw, *, require_immutable=True, keys=KEYS,
                  allow_prerelease=False):
    # The fresh feed is the current authority. Immutable metadata is historical
    # evidence for the same bytes, and may outlive its original freshness window.
    envelope = json.loads(raw,object_pairs_hook=unique)
    issued = envelope['manifest']['issued_at']
    archived = verify_manifest(raw,keys,now=issued)
    identity = ('version','build','size','sha256','url','data_contract','min_version','channel','platform')
    if any(archived[key]!=manifest[key] for key in identity):
        raise ValueError('Archived release identifies different bytes or compatibility')
    name = alias(manifest['version'])
    if (type(release) is not dict or release.get('tag_name')!='v'+manifest['version'] or
            type(release.get('prerelease')) is not bool or
            (release['prerelease'] and allow_prerelease is not True)):
        raise ValueError('Release is not a public stable mirror')
    if require_immutable:
        if release.get('draft') is not False or release.get('immutable') is not True:
            raise ValueError('Published release must be immutable')
    elif release.get('draft') is not True:
        raise ValueError('Pre-publication checks require the actual draft')
    assets = release.get('assets',[])
    if len(assets)!=3 or {a.get('name') for a in assets}!={name,name+'.sha256','signed-manifest.json'}:
        raise ValueError('Ambiguous public release assets')
    for item in assets:
        if item.get('state')!='uploaded':
            raise ValueError('Public asset upload incomplete')
        if require_immutable and item.get('browser_download_url')!=asset_url(manifest['version'], item['name']):
            raise ValueError('Unexpected public asset location')
        if not require_immutable:
            if (type(item.get('id')) is not int or item['id']<=0 or item.get('url')!=
                    'https://api.github.com/repos/'+REPOSITORY+'/releases/assets/'+str(item['id'])):
                raise ValueError('Draft asset belongs to an unexpected repository')
    installer = next(a for a in assets if a['name']==name)
    if installer.get('size')!=manifest['size'] or installer.get('digest')!='sha256:'+manifest['sha256']:
        raise ValueError('Public installer identity mismatch')
    for name,body in asset_contents(manifest,raw).items():
        asset = next(a for a in assets if a['name']==name)
        if asset.get('size')!=len(body) or asset.get('digest')!='sha256:'+hashlib.sha256(body).hexdigest():
            raise ValueError('Public verification asset identity mismatch')
    return installer


def gh(*args, missing=False):
    result = subprocess.run(['gh',*args],capture_output=True,text=True,encoding='utf-8')
    if result.returncode:
        if missing and '(HTTP 404)' in result.stderr:
            return None
        raise RuntimeError('GitHub operation failed: '+args[0])
    if args[0]=='api':
        return json.loads(result.stdout) if result.stdout.strip() else None
    return result.stdout.strip() or None


def release_by_tag(tag):
    result = gh('api','repos/'+REPOSITORY+'/releases/tags/'+tag,missing=True)
    if result is not None: return result
    # GitHub may not create the Git tag until the draft is published.
    candidates = gh('api','repos/'+REPOSITORY+'/releases?per_page=100')
    found = [r for r in candidates if r.get('tag_name')==tag]
    if len(found)>1: raise ValueError('Ambiguous release')
    return found[0] if found else None


def safe_path(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or (part.exists() and getattr(part.lstat(), 'st_file_attributes', 0)&0x400):
            raise ValueError('Redirected local distribution path')
    return path


def regular_file(path, maximum):
    path = safe_path(path)
    value = path.stat()
    if not stat.S_ISREG(value.st_mode) or not 1 <= value.st_size <= maximum:
        raise ValueError('Bounded regular input file required')
    return path


def unchanged_feed(raw):
    if read_bytes(FEED, 65536) != raw:
        raise ValueError('Stable feed changed; inspect retained draft/release before retry')
    verify_manifest(raw)  # Recheck expiry after network/copy/upload work.


def release_id(release):
    number = release.get('id')
    if type(number) is not int or number <= 0:
        raise ValueError('Exact GitHub release ID required')
    return number


def publish_draft(release, manifest, raw, paths, notes, guard, *, prerelease=False):
    """Complete an exact draft; never replace existing assets or tags."""
    tag = 'v'+manifest['version']
    guard()
    if release is None:
        args = ['release','create',tag,'--repo',REPOSITORY,'--draft','--target','main',
                '--title','ShortFlow '+manifest['version'],'--notes-file',str(notes)]
        if prerelease:
            args += ['--prerelease']  # A draft cannot be latest; publish PATCH explicitly keeps it false.
        gh(*args)
        release = release_by_tag(tag)
    if release is None:
        raise ValueError('Created draft identity could not be verified')
    endpoint = 'repos/'+REPOSITORY+'/releases/'+str(release_id(release))
    if (release.get('tag_name') != tag or release.get('draft') is not True
            or release.get('prerelease') is not prerelease):
        raise ValueError('Unexpected interrupted release state')
    existing = release.get('assets', [])
    if len({a['name'] for a in existing}) != len(existing) or any(a['name'] not in paths for a in existing):
        raise ValueError('Unexpected draft asset')
    for asset in existing:
        asset_id = asset.get('id')
        if (type(asset_id) is not int or asset_id <= 0 or asset.get('url') !=
                'https://api.github.com/repos/'+REPOSITORY+'/releases/assets/'+str(asset_id)):
            raise ValueError('Existing draft asset belongs to an unexpected repository')
        path = regular_file(paths[asset['name']], 1500*1024*1024)
        with path.open('rb') as source:
            wanted = hashlib.file_digest(source, 'sha256').hexdigest()
        if (asset.get('size') != path.stat().st_size or asset.get('digest') != 'sha256:'+wanted
                or asset.get('state') != 'uploaded'):
            raise ValueError('Draft asset changed; refusing overwrite')
    present = {a['name'] for a in existing}
    for name, path in paths.items():
        if name not in present:
            guard()
            regular_file(path, 1500*1024*1024)
            gh('release','upload',tag,str(path),'--repo',REPOSITORY)
    candidate = gh('api', endpoint)
    match_release(candidate, manifest, raw, require_immutable=False, allow_prerelease=prerelease)
    guard()
    published = gh('api', endpoint, '--method','PATCH','-F','draft=false',
                   '-F','prerelease='+str(prerelease).lower(),
                   '-f','make_latest='+('false' if prerelease else 'true'))
    match_release(published, manifest, raw, allow_prerelease=prerelease)
    if release_id(published) != release_id(candidate) or published['prerelease'] is not prerelease:
        raise ValueError('Published release identity/state mismatch')
    return published


def promote_current(release, manifest, archived, live_raw):
    """Only current fresh stable authority may change prerelease/latest metadata.

    Immutable assets and tag are never edited. GitHub explicitly permits these
    two release flags on an immutable release. Catalog's default remains strict.
    """
    was_prerelease = release.get('prerelease') is True
    match_release(release, manifest, archived, allow_prerelease=was_prerelease)
    number = release_id(release)
    unchanged_feed(live_raw)
    latest = gh('api', 'repos/'+REPOSITORY+'/releases/latest', missing=True)
    if not was_prerelease and latest is not None and latest.get('id') == number:
        return dict(version=manifest['version'], sha256=manifest['sha256'], already_mirrored=True)
    unchanged_feed(live_raw)
    promoted = gh('api', 'repos/'+REPOSITORY+'/releases/'+str(number), '--method','PATCH',
                  '-F','prerelease=false','-f','make_latest=true')
    match_release(promoted, manifest, archived)
    if release_id(promoted) != number:
        raise ValueError('Promotion identity mismatch')
    latest = gh('api','repos/'+REPOSITORY+'/releases/latest')
    if latest.get('id') != number:
        raise ValueError('Latest release did not match current stable; inspect, never overwrite assets')
    unchanged_feed(live_raw)
    return dict(version=manifest['version'], sha256=manifest['sha256'], already_mirrored=True,
                promoted=was_prerelease, latest_updated=True)


def write_owned(path, raw):
    path = safe_path(path)
    if path.exists():
        if regular_file(path, 65536).read_bytes() != raw:
            raise ValueError('Unrelated or changed local verification file')
    else:
        with path.open('xb') as output:
            output.write(raw)


def prepublish(directory, accepted_manifest, accepted_installer, *, keep_latest=False):
    """Explicit local owner prepublication, not a new stable feed authority.

    Fresh signed STABLE candidate + accepted bytes may be published as an immutable
    GitHub PRERELEASE. No workflow/cron use; no latest switch; no VPS download.
    """
    if keep_latest is not True or os.environ.get('GITHUB_ACTIONS') or os.environ.get('CI', '').lower() == 'true':
        raise ValueError('Explicit local --keep-latest mode only; never CI')
    raw = regular_file(accepted_manifest, 65536).read_bytes()
    candidate = verify_manifest(raw)
    installer = regular_file(accepted_installer, 1500*1024*1024)
    verify_file(installer, candidate)
    baseline_raw = read_bytes(FEED, 65536)
    baseline = verify_manifest(baseline_raw)
    if versions(candidate['version']) <= versions(baseline['version']):
        raise ValueError('Prepublication candidate must be newer than current fresh stable')
    if gh('api', 'user').get('login') != 'sem199318-sudo':
        raise ValueError('Existing local owner GitHub CLI login required')
    repository = gh('api', 'repos/'+REPOSITORY)
    if repository.get('private') is not False or repository.get('full_name') != REPOSITORY:
        raise ValueError('Fixed public distribution repository required')
    latest_before = gh('api', 'repos/'+REPOSITORY+'/releases/latest', missing=True)

    def guard():
        verify_manifest(raw)
        unchanged_feed(baseline_raw)
        verify_file(installer, candidate)

    release = release_by_tag('v'+candidate['version'])
    if release is not None and release.get('draft') is False:
        archived = read_asset(candidate['version'], 'signed-manifest.json', 65536)
        match_release(release, candidate, archived, allow_prerelease=True)
        if release.get('prerelease') is not True:
            raise ValueError('Already-published full release is not a prepublication candidate')
        guard()
        latest_after = gh('api', 'repos/'+REPOSITORY+'/releases/latest', missing=True)
        if (latest_after or {}).get('id') != (latest_before or {}).get('id'):
            raise ValueError('Latest changed concurrently; inspect, no automatic rollback')
        return dict(version=candidate['version'], sha256=candidate['sha256'], already_mirrored=True,
                    prepublished=True, prerelease=True, latest_unchanged=True)
    work = safe_path(directory)
    allowed = {alias(candidate['version']), alias(candidate['version'])+'.sha256', 'signed-manifest.json', 'notes.txt'}
    if work.exists():
        if not work.is_dir() or any(p.name not in allowed for p in work.iterdir()):
            raise ValueError('Prepublication work directory must contain only its exact owned files')
    else:
        work.mkdir(parents=True)
    package = safe_path(work / alias(candidate['version']))
    if package.exists():
        verify_file(package, candidate)
    else:
        count = 0
        with installer.open('rb') as source, package.open('xb') as output:
            while chunk := source.read(256*1024):
                count += len(chunk)
                if count > candidate['size']:
                    raise ValueError('Accepted installer changed while copying')
                output.write(chunk)
            output.flush(); os.fsync(output.fileno())
        verify_file(package, candidate)
    for name, body in asset_contents(candidate, raw).items():
        write_owned(work / name, body)
    notes = work / 'notes.txt'
    write_owned(notes, ('ShortFlow '+candidate['version']+' for Windows x64.\n\n'+
        candidate['notes']+'\n\nInstaller bytes are verified against the owner-accepted '
        'Ed25519-signed manifest. This is not an Authenticode publisher signature.\n').encode('utf-8'))
    paths = {p.name:p for p in (package, work/(alias(candidate['version'])+'.sha256'), work/'signed-manifest.json')}
    published = publish_draft(release, candidate, raw, paths, notes, guard, prerelease=True)
    latest_after = gh('api', 'repos/'+REPOSITORY+'/releases/latest', missing=True)
    if (latest_after or {}).get('id') != (latest_before or {}).get('id'):
        raise ValueError('Latest changed concurrently; inspect, no automatic rollback')
    guard()
    return dict(version=candidate['version'], sha256=candidate['sha256'], size=candidate['size'],
                release_id=release_id(published), prepublished=True, prerelease=True, latest_unchanged=True)


def mirror(directory):
    context = os.environ.get('GITHUB_REPOSITORY',REPOSITORY)
    if context!=REPOSITORY:
        raise ValueError('Unexpected workflow repository')
    repository = gh('api','repos/'+REPOSITORY)
    if repository.get('private') is not False or repository.get('full_name')!=REPOSITORY:
        raise ValueError('Public distribution repository required')
    raw = read_bytes(FEED,65536)
    manifest = verify_manifest(raw)
    version = manifest['version']
    tag = 'v'+version
    release = release_by_tag(tag)
    if release is not None and release.get('draft') is False:
        archived = read_asset(version,'signed-manifest.json',65536)
        return promote_current(release, manifest, archived, raw)
    work = Path(directory).absolute()
    work.mkdir(parents=True,exist_ok=True)
    name = alias(version)
    installer = work/name
    if not installer.exists():
        temporary = work/(name+'.partial')
        if temporary.exists():
            raise ValueError('Unfinished installer download; inspect before resuming')
        try:
            with response(manifest['url']) as source, temporary.open('xb') as target:
                if source.status!=200 or int(source.headers.get('Content-Length','0'))!=manifest['size']:
                    raise ValueError('Unexpected installer response')
                count = 0
                while chunk:=source.read(256*1024):
                    count+=len(chunk)
                    if count>manifest['size']:
                        raise ValueError('Installer exceeded signed size')
                    target.write(chunk)
            verify_file(temporary,manifest)
            temporary.rename(installer)
        finally:
            if temporary.exists(): temporary.unlink()
    verify_file(installer,manifest)
    write_verification_assets(work,manifest,raw)
    checksum = work/(name+'.sha256')
    metadata = work/'signed-manifest.json'
    notes = work/'notes.txt'
    notes.write_text('ShortFlow '+version+' for Windows x64.\n\n'+manifest['notes']+
        '\n\nInstaller bytes are verified against the existing Ed25519-signed stable feed.\n'+
        'This is not an Authenticode publisher signature.\n',encoding='utf-8')
    expected = {p.name:p for p in (installer,checksum,metadata)}
    publish_draft(release, manifest, raw, expected, notes, lambda: unchanged_feed(raw))
    return dict(version=version,sha256=manifest['sha256'],size=manifest['size'],mirrored=True)


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workdir',required=True)
    parser.add_argument('--accepted-manifest',type=Path)
    parser.add_argument('--accepted-installer',type=Path)
    parser.add_argument('--keep-latest',action='store_true')
    args = parser.parse_args()
    if args.accepted_manifest or args.accepted_installer or args.keep_latest:
        if not (args.accepted_manifest and args.accepted_installer and args.keep_latest):
            parser.error('Local prepublication requires both accepted inputs and --keep-latest')
        result = prepublish(args.workdir, args.accepted_manifest, args.accepted_installer, keep_latest=True)
    else:
        result = mirror(args.workdir)
    print(json.dumps(result,sort_keys=True))
