"""Distribute only bytes authorized by ShortFlow's existing signed stable feed.

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
    path = Path(path)
    if path.is_symlink() or path.stat().st_size!=manifest['size']:
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


def match_release(release, manifest, raw, *, require_immutable=True, keys=KEYS):
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
            release.get('prerelease') is not False):
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
        match_release(release,manifest,archived)
        return dict(version=version,sha256=manifest['sha256'],already_mirrored=True)
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
    checksum = work/(name+'.sha256')
    checksum.write_text(manifest['sha256']+'  '+name+'\n',encoding='ascii')
    metadata = work/'signed-manifest.json'
    metadata.write_bytes(raw)
    notes = work/'notes.txt'
    notes.write_text('ShortFlow '+version+' for Windows x64.\n\n'+manifest['notes']+
        '\n\nInstaller bytes are verified against the existing Ed25519-signed stable feed.\n'+
        'This is not an Authenticode publisher signature.\n',encoding='utf-8')
    if release is None:
        gh('release','create',tag,'--repo',REPOSITORY,'--draft','--target','main',
           '--title','ShortFlow '+version,'--notes-file',str(notes))
        release = release_by_tag(tag)
    if release is None or type(release.get('id')) is not int:
        raise ValueError('Created draft identity could not be verified')
    endpoint = 'repos/'+REPOSITORY+'/releases/'+str(release['id'])
    if release.get('draft') is not True or release.get('prerelease') is not False:
        raise ValueError('Unexpected interrupted release state')
    expected = {p.name:p for p in (installer,checksum,metadata)}
    existing = release.get('assets',[])
    if len({a['name'] for a in existing})!=len(existing) or any(a['name'] not in expected for a in existing):
        raise ValueError('Unexpected draft asset')
    for asset in existing:
        path = expected[asset['name']]
        with path.open('rb') as source: wanted = hashlib.file_digest(source,'sha256').hexdigest()
        if asset.get('size')!=path.stat().st_size or asset.get('digest')!='sha256:'+wanted or asset.get('state')!='uploaded':
            raise ValueError('Draft asset changed; refusing overwrite')
    names = {a['name'] for a in existing}
    for name,path in expected.items():
        if name not in names:
            gh('release','upload',tag,str(path),'--repo',REPOSITORY)
    candidate = gh('api',endpoint)
    match_release(candidate,manifest,raw,require_immutable=False)
    # The authority must still name these exact bytes after network transfer.
    if read_bytes(FEED,65536)!=raw:
        raise ValueError('Stable feed changed while mirroring; draft retained')
    verify_manifest(raw)
    gh('release','edit',tag,'--repo',REPOSITORY,'--draft=false','--latest')
    match_release(gh('api',endpoint),manifest,raw)
    return dict(version=version,sha256=manifest['sha256'],size=manifest['size'],mirrored=True)


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workdir',required=True)
    args = parser.parse_args()
    print(json.dumps(mirror(args.workdir),sort_keys=True))
