#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TG_BOT_TOKEN='1:testtoken' TG_ADMIN_IDS='1' python3 - "$root/tgbot.py" <<'PY'
import importlib.util, json, os, sys, time
spec=importlib.util.spec_from_file_location('bot',sys.argv[1]); bot=importlib.util.module_from_spec(spec); spec.loader.exec_module(bot)
class Resp:
 def read(self): return b'{"ok":true,"result":[]}'
class Conn:
 made=[]
 def __init__(self,host,timeout): self.host=host; self.timeout=timeout; self.closed=False; Conn.made.append(self)
 def request(self,*a,**k): pass
 def getresponse(self): return Resp()
 def close(self): self.closed=True
old=Conn('old',70); bot._TG_LOCAL.conn=old; bot._TG_LOCAL.last_used=time.monotonic()-60
bot.http.client.HTTPSConnection=Conn
assert bot.tg('sendMessage',chat_id=1,text='x')['ok']
assert old.closed, 'idle connection was reused'
assert Conn.made[-1].timeout == 15, Conn.made[-1].timeout
bot._TG_LOCAL.conn=None
assert bot.tg('getUpdates',timeout=50)['ok']
assert Conn.made[-1].timeout == 70, Conn.made[-1].timeout
print('telegram connection lifecycle OK', flush=True)
os._exit(0)
PY
