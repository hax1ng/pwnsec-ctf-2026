#!/usr/bin/env python3
# Upload an adversarial WAV to /transcribe, request JSON, and save the returned
# (base64-encoded) WAV response — used to deliver the exploit and capture the flag audio.
import argparse, base64, hashlib, json, pathlib, requests, time
URL='https://CHALLENGE_HOST/transcribe'
p=argparse.ArgumentParser()
p.add_argument('-o','--output',required=True)
p.add_argument('-f','--file',default='silence.wav')
p.add_argument('args',nargs='*')
a=p.parse_args()
with open(a.file,'rb') as f:
    fields=[('file',(pathlib.Path(a.file).name,f,'application/octet-stream'))]
    data=[('response_format','json')]+[('arg',x) for x in a.args]
    t=time.time(); r=requests.post(URL,files=fields,data=data,timeout=30); dt=time.time()-t
print('status',r.status_code,'elapsed',round(dt,3),'type',r.headers.get('content-type'),'len',len(r.content))
pathlib.Path(a.output+'.json').write_bytes(r.content)
try:
 d=r.json(); print('keys',d.keys()); print('error',d.get('error'))
 u=d.get('audio_data_url',''); b=base64.b64decode(u.partition(',')[2]); pathlib.Path(a.output+'.wav').write_bytes(b)
 print('wav',len(b),hashlib.sha256(b).hexdigest())
except Exception as e: print('decode error',e,repr(r.text[:500]))
