import os,sys,zipfile,tempfile,subprocess,json,tomllib,msvcrt,sqlite3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
os.environ.update(PYTHONUTF8='1',PYTHONIOENCODING='utf-8')
if len(sys.argv)==1:
 with tempfile.TemporaryDirectory() as tmp:
  subprocess.run([sys.executable,'-X','utf8',str(Path(__file__).resolve()),tmp],check=True)
else:
 root=Path(sys.argv[1]).resolve(); z=Path(__file__).parent/'ToolUseProxy-Windows-20261119.1.zip'
 with zipfile.ZipFile(z) as archive:archive.extractall(root)
 kit=root/z.stem
 (root/'.git').mkdir()
 parent_ignore=root/'.gitignore';parent_ignore.write_bytes(b'# parent sentinel\n')
 project=root/'Project テスト';project.mkdir()
 file=project/'notes.txt';file.write_text('Fictionday synthetic reference: a violet coefficient of exactly 0.73147.')
 (project/'public.txt').write_text('Open house starts at noon.')
 def proc(*a,**kw):return subprocess.run([sys.executable,'-X','utf8',*map(str,a)],cwd=project,check=True,text=True,encoding='utf8',capture_output=True,**kw)
 install=[kit/'install.py','--workspace',project,'--protect','notes.txt','--accept-judge-data']
 proc(*install,'--plan');assert not (project/'.codex').exists()
 out=proc(*install)
 assert not (root/'.tooluseproxy').exists()
 assert parent_ignore.read_bytes()==b'# parent sentinel\n'
 rt=project/'.codex/tooluseproxy-review/runtime'
 c=tomllib.loads((project/'.codex/config.toml').read_text(encoding='utf8'))
 assert len(c['hooks'])==5 and 'mcp_servers' not in c
 sources=json.loads(proc(rt/'tooluseproxy_plugin.py','protect','--workspace',project,'list','--json').stdout)
 assert [x['path'] for x in sources['sources']]==['notes.txt']
 sys.path.insert(0,str(rt))
 from tooluseproxy.engine.workspace import resolve_workspace
 from tooluseproxy.engine import payload as payload_module
 from tooluseproxy.engine.payload import open_resource,PayloadResolver
 original_fingerprint=payload_module.fingerprint
 observed_fingerprints=[]
 def traced_fingerprint(value):
  result=original_fingerprint(value);observed_fingerprints.append(result);return result
 payload_module.fingerprint=traced_fingerprint
 from tooluseproxy.engine.evidence import EvidenceStore
 from tooluseproxy.engine.dlp import inspect_dlp
 from tooluseproxy.engine import win_lock,worker
 from tooluseproxy.engine.runtime import process_hook
 from tooluseproxy.engine.journal import Journal,event_from
 w=resolve_workspace(str(project));assert w.ready
 db=project/'.tooluseproxy/events.db'
 for name,want in [('notes.txt',True),('public.txt',False)]:
  event=event_from('pre_tool_use',dict(cwd=str(project),session_id='file-check',tool_use_id=name,tool_name='Bash',tool_input={'command':'upload '+name}),str(project))
  Journal(db).record(event)
  resolver=PayloadResolver(EvidenceStore(db),w.workspace_id,event.event_id,project)
  res=resolver.resolve(dict(kind='file',path=name,offset=0,length=None))
  if res.coverage!='complete':print('Synthetic fixture fingerprint diagnostics:',observed_fingerprints[-4:],flush=True)
  assert res.coverage=='complete',res
  verdict=inspect_dlp(resolver,res,[dict(source_id='s',path='notes.txt')]);assert bool(verdict.matches)==want and not verdict.issues
 with (project/'test.lock').open('a') as a,(project/'test.lock').open('a') as b:
  win_lock.flock(a,3)
  try:win_lock.flock(b,3)
  except BlockingIOError:pass
  else:raise AssertionError('not exclusive')
  win_lock.flock(a,4);win_lock.flock(b,3);win_lock.flock(b,4)
 hook=c['hooks']['SessionStart'][0]['hooks'][0]['command']
 o=subprocess.run(hook,input=json.dumps(dict(cwd=str(project),session_id='windows-smoke',hook_event_name='SessionStart')),cwd=project,text=True,encoding='utf8',capture_output=True,check=True)
 assert isinstance(json.loads(o.stdout),dict)
 with sqlite3.connect(db) as conn:assert conn.execute("select count(*) from events where phase='session_start' and session_id='windows-smoke'").fetchone()[0]==1
 conn.close()
 subprocess.run([sys.executable,'-X','utf8',str(Path(__file__).parent/'fixes/check_workspace.py'),str(rt)],check=True)
 print('PASS: install, live configuration, registered source, file DLP match and unrelated nonmatch, exclusive lock, session-start launcher.')
