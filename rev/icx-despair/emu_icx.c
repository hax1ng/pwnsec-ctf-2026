#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MASK 0x7fffffu
static uint32_t *phys, *mem, R[16], *cs;
static uint64_t steps;
static unsigned csp;
static unsigned unkprints;
static uint32_t prevpc;
static unsigned tabprints; static uint64_t tabreads;
static unsigned tgtprints;
static unsigned stageprints[8];
static inline int32_t sx(uint32_t x,unsigned n){uint32_t s=1u<<(n-1);return (int32_t)((x^s)-s);}
static inline int32_t s23(uint32_t x){return sx(x&MASK,23);}
static inline uint32_t rol23(uint32_t x,uint32_t n){n%=23;x&=MASK;return n?((x<<n)|(x>>(23-n)))&MASK:x;}
static uint32_t run(uint32_t pc,uint64_t limit){
 R[13]=(R[13]-1)&MASK; mem[R[13]]=MASK; /* synthetic return */
 for(;steps<limit;steps++){
  uint32_t at=pc,w=mem[pc]&MASK; pc=(pc+1)&MASK;
  if(at==0xa4b0a && tgtprints<600){
   uint32_t rc=R[12], idx=mem[(rc-0x2e)&MASK]&MASK;
   fprintf(stderr,"TGT n=%u iter=%u idx=%u op=%u actual=%06x olderr=%06x aux2a=%06x aux6=%06x desc=%06x\n",
    tgtprints,mem[(rc-0x14)&MASK]&MASK,idx,mem[(rc-0x2d)&MASK]&MASK,
    mem[(rc-0x5e)&MASK]&MASK,mem[(rc-0xc)&MASK]&MASK,
    mem[(rc-0x2a)&MASK]&MASK,mem[(rc-0x6)&MASK]&MASK,
    mem[(mem[(rc-0x5)&MASK]+0x10+idx)&MASK]&MASK);
   tgtprints++;
  }
  if(at==0xa46c2 && stageprints[3]++<12){uint32_t rc=R[12];fprintf(stderr,"S3 idx=%u src=%u bit=%u s7=%06x s8=%06x s9=%06x\n",mem[(rc-0x2e)&MASK],mem[(rc-0x4e)&MASK],mem[(rc-0x49)&MASK],mem[(rc-7)&MASK],mem[(rc-8)&MASK],mem[(rc-9)&MASK]);}
  if(at==0xa47b3 && stageprints[4]++<12){uint32_t rc=R[12];fprintf(stderr,"S4 idx=%u src=%u bit=%u s7=%06x s8=%06x s9=%06x\n",mem[(rc-0x2e)&MASK],mem[(rc-0x51)&MASK],mem[(rc-0x52)&MASK],mem[(rc-7)&MASK],mem[(rc-8)&MASK],mem[(rc-9)&MASK]);}
  if(at==0xa47b3){uint32_t rc=R[12];fprintf(stderr,"MAP4 %u %u %u\n",mem[(rc-0x2e)&MASK],mem[(rc-0x51)&MASK],mem[(rc-0x4f)&MASK]&1);}
  if(at==0xa4878){uint32_t rc=R[12];fprintf(stderr,"MAP5 %u %u %u\n",mem[(rc-0x2e)&MASK],mem[(rc-0x53)&MASK],mem[(rc-0x54)&MASK]&1);}
  if(at==0xa49f3){uint32_t rc=R[12],i=mem[(rc-0x2e)&MASK];uint32_t in=(mem[(mem[(rc-4)&MASK]+0xad+i/23)&MASK]>>(i%23))&1;fprintf(stderr,"MAP6 %u %u\n",i,(mem[(rc-0x58)&MASK]&1)^in);}
  if(at==0xa4acc){uint32_t rc=R[12];fprintf(stderr,"QKEY %u %u %06x\n",mem[(rc-0x2e)&MASK],mem[(rc-0x5b)&MASK]&15,R[1]);}
  if(at==0xa4af9){uint32_t rc=R[12];fprintf(stderr,"QROT %u %u\n",mem[(rc-0x2e)&MASK],R[0]&3);}
  if(at==0xa4b33) fprintf(stderr,"TGTH n=%u H=%06x sp=%06x stk=%06x,%06x,%06x,%06x\n",tgtprints-1,R[0],R[13],mem[R[13]]&MASK,mem[(R[13]+1)&MASK]&MASK,mem[(R[13]+2)&MASK]&MASK,mem[(R[13]+3)&MASK]&MASK);
  if(at==0xa436c){uint32_t rc=R[12];fprintf(stderr,"FSEIN idx=%u key=%06x state=%u sym=%u\n",mem[(rc-0x2e)&MASK],mem[(rc-0x2b)&MASK],mem[(rc-0xb)&MASK],mem[(rc-0x39)&MASK]);}
  if(at==0xa4e46){fprintf(stderr,"ENTER FAIL from=%06x step=%llu r0=%llx rc=%06x\n",prevpc,(unsigned long long)steps,(unsigned long long)R[0],R[12]);for(int q=1;q<=0x6a;q++)fprintf(stderr,"L-%02x=%06x%c",q,mem[(R[12]-q)&MASK]&MASK,q%8?' ':'\n');fputc('\n',stderr);}
  if((at==0xa3e8e||at==0xa3ea9||at==0xa3ec9||at==0xa3ee9||at==0xa3f09||at==0xa3f29)) fprintf(stderr,"HDRV pc=%06x ret=%06x sp=%06x\n",at,R[0],R[13]);
  prevpc=at;
  uint32_t op=w>>16,d=(w>>12)&15,a=(w>>8)&15,b=(w>>4)&15,ad,n; int32_t off;
  switch(op){
  case 0x32: case 0x3a: break;
  case 0x42:R[d]=(R[a]+R[b])&MASK;break; case 0x35:R[d]=(R[a]-R[b])&MASK;break;
  case 0x05:R[d]=(uint32_t)((uint64_t)R[a]*R[b])&MASK;break;
  case 0x2a:R[d]=R[b]?R[a]/R[b]:0;break; case 0x09:R[d]=R[b]?R[a]%R[b]:0;break;
  case 0x24:R[d]=R[b]?(uint32_t)(s23(R[a])/s23(R[b]))&MASK:0;break;
  case 0x48:R[d]=R[b]?(uint32_t)(s23(R[a])%s23(R[b]))&MASK:0;break;
  case 0x23:R[d]=R[a]&R[b];break;case 0x57:R[d]=R[a]|R[b];break;case 0x79:R[d]=R[a]^R[b];break;
  case 0x3f:R[d]=(~R[d])&MASK;break;case 0x6d:R[d]=(R[b]>=32?0:(R[a]<<R[b]))&MASK;break;
  case 0x43:R[d]=R[b]>=32?0:R[a]>>R[b];break;case 0x66:R[d]=(uint32_t)(s23(R[a])>>R[b])&MASK;break;
  case 0x14:R[d]=rol23(R[a],R[b]);break;case 0x78:R[d]=rol23(R[a],23-(R[b]%23));break;
  case 0x1a:R[d]=R[a]==R[b];break;case 0x22:R[d]=R[a]!=R[b];break;
  case 0x4c:R[d]=R[a]<R[b];break;case 0x10:R[d]=R[a]<=R[b];break;
  case 0x70:R[d]=s23(R[a])<s23(R[b]);break;case 0x5d:R[d]=s23(R[a])<=s23(R[b]);break;
  case 0x31:R[d]=R[a];break;case 0x2e:R[d]=(uint32_t)sx(w&0xfff,12)&MASK;break;
  case 0x51:R[d]=mem[pc]&MASK;pc=(pc+1)&MASK;break;
  case 0x37:ad=(R[a]+sx(w&255,8))&MASK;if(ad>=0x100000&&ad<0x110000){tabreads++;if(tabprints<200){fprintf(stderr,"TABREAD idx=%04x pc=%06x val=%06x step=%llu\n",ad-0x100000,at,mem[ad]&MASK,(unsigned long long)steps);tabprints++;}}if(unkprints<20 && !((ad>=0xa0000&&ad<0xc0000)||(ad>=0x600000&&ad<0x710000))){fprintf(stderr,"UNKNOWN LOAD ad=%06x pc=%06x step=%llu\n",ad,at,(unsigned long long)steps);unkprints++;}R[d]=mem[ad]&MASK;break;
  case 0x4a:ad=(R[a]+sx(w&255,8))&MASK;if(ad>=0xa0000&&ad<0xa8800){fprintf(stderr,"CODE WRITE at=%06x bypc=%06x val=%06x step=%llu\n",ad,at,R[d],(unsigned long long)steps);exit(4);}mem[ad]=R[d]&MASK;break;
  case 0x7d:R[d]=(R[a]+sx(w&255,8))&MASK;break;
  case 0x04:pc=(pc+sx(w&65535,16))&MASK;break;
  /* B16 has no register field.  Conditional branches consume the zero
     condition from the immediately preceding ALU/compare instruction. */
  case 0x75:{uint32_t pw=mem[(at-1)&MASK],pd=(pw>>12)&15;if(R[pd]==0)pc=(pc+sx(w&65535,16))&MASK;break;}
  case 0x27:{uint32_t pw=mem[(at-1)&MASK],pd=(pw>>12)&15;if(R[pd]!=0)pc=(pc+sx(w&65535,16))&MASK;break;}
  case 0x1b:R[13]=(R[13]-1)&MASK;mem[R[13]]=pc;pc=(pc+sx(w&65535,16))&MASK;break;
  case 0x63:R[13]=(R[13]-1)&MASK;mem[R[13]]=pc;pc=R[d];break;
  case 0x73:pc=mem[R[13]]&MASK;R[13]=(R[13]+1)&MASK;if(pc==MASK)return R[0];break;
  case 0x7a:R[13]=(R[13]-1)&MASK;mem[R[13]]=R[d]&MASK;break;
  case 0x36:R[d]=mem[R[13]]&MASK;R[13]=(R[13]+1)&MASK;break;
  default:fprintf(stderr,"bad op %02x word %06x pc %06x steps %llu\n",op,w,at,(unsigned long long)steps);exit(2);
  }
  if((steps%1000000000ull)==0 && steps)fprintf(stderr,"steps=%llu pc=%06x depth=%u\n",(unsigned long long)steps,pc,csp);
 }
 fprintf(stderr,"step limit pc=%06x\n",pc);exit(3);
}
int main(int ac,char**av){
 if(ac<2){fprintf(stderr,"usage: %s logical.bin [96-byte-input]\n",av[0]);return 1;}
 int fromstate=av[1][0]=='@';
 FILE*f=fopen(av[1][0]=='@'?av[1]+1:av[1],"rb");phys=calloc(1<<23,4);mem=calloc(1<<23,4);cs=malloc(1<<24);
 if(fromstate){
  if(!f||fread(mem,4,1<<23,f)!=(1<<23)){perror("read state");return 1;} fclose(f);
  goto have_state;
 }
 if(!f||fread(phys,4,1<<23,f)!=(1<<23)){perror("read");return 1;}fclose(f);
 memcpy(mem+0xa0000,phys+0x340000,0x8800*4);
 memcpy(mem+0xb0000,phys+0x348800,0x500*4);
 /* Mappings recovered by invoking the native MMU page-walk at the prompt. */
 memcpy(mem+0xc0000,phys+0x57f000,0x1000*4);
 /* The loader maps the complete two-million-word system-volume window:
    virtual 0x100000..0x2fffff -> physical 0x580000..0x77ffff. */
 memcpy(mem+0x100000,phys+0x580000,0x200000*4);
 unsigned char inbuf[96]; const unsigned char*in;
load_input:
 if(ac>2 && av[2][0]=='@') { FILE*fi=fopen(av[2]+1,"rb"); if(!fi||fread(inbuf,1,96,fi)!=96){perror("input file");return 1;} if(fi)fclose(fi); in=inbuf; }
 else { const char*s=ac>2?av[2]:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; if(strlen(s)!=96){fprintf(stderr,"input must be 96 bytes\n");return 1;} in=(const unsigned char*)s; }
 if(fromstate){for(unsigned i=0;i<96;i++)mem[0xb0440+i]=in[i];R[13]=0x700000;goto do_gate;}
 for(unsigned i=0;i<96;i++)mem[0xb0040+i]=in[i];
 for(unsigned i=0;i<8;i++)mem[0xb04a0+i]=mem[0xb0000+i];mem[0xb04a1]=0xb04b8;
 for(unsigned i=0;i<96;i++)mem[0xb0440+i]=mem[0xb0040+i];
 R[13]=0x700000;R[0]=0xb0020;
 uint32_t x=run(0xa2469,100000000000ull);
 fprintf(stderr,"setup=%06x steps=%llu\n",x,(unsigned long long)steps);
 R[0]=0xb0020;x=run(0xa34f6,100000000000ull);
 fprintf(stderr,"verify=%06x steps=%llu\n",x,(unsigned long long)steps);
 fprintf(stderr,"tabreads=%llu\n",(unsigned long long)tabreads);
 FILE*pre=fopen("pre_gate.bin","wb");fwrite(mem,4,1<<23,pre);fclose(pre);
 goto do_gate;
have_state:
 if(ac>2 && !strcmp(av[2],"--dump-fse")){
  uint32_t key=ac>3?(uint32_t)strtoul(av[3],0,0):0x41ba7c;
  const uint32_t out=0xb1000;
  for(unsigned st=0;st<128;st++)for(unsigned sym=0;sym<32;sym++){
   memset(R,0,sizeof(R)); R[13]=0x700000;
   mem[out]=mem[out+1]=mem[out+2]=0;
   R[0]=key; R[1]=sym; R[2]=st; R[3]=out;
   run(0xa3810,steps+100000000ull);
   printf("FSE %u %u %u %u %u\n",st,sym,mem[out],mem[out+1],mem[out+2]);
  }
  return 0;
 }
 goto load_input;
do_gate:
 R[0]=0xb0440;R[1]=0x60;R[2]=0xb0020;R[3]=0xb00c0;
 x=run(0xa3d3d,100000000000ull);
 fprintf(stderr,"gatecheck=%06x steps=%llu\n",x,(unsigned long long)steps);
 printf("B20:");for(unsigned i=0;i<0x60;i++)printf(" %06x",mem[0xb0020+i]);puts("");
 FILE*o=fopen("emu_mem.bin","wb");fwrite(mem,4,1<<23,o);fclose(o);
}
