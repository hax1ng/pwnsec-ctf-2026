/* Race-capture tool: inotify-watch a dir and hard-link AURA.gb the instant it
 * is written, before the VMProtect-packed layer2.exe deletes it.
 * usage: ./watch <dir-to-watch> <output-link-path> */
#define _GNU_SOURCE
#include <sys/inotify.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
int main(int argc,char**argv){
 if(argc<3)return 1; int fd=inotify_init1(0); int wd=inotify_add_watch(fd,argv[1],IN_CREATE|IN_CLOSE_WRITE|IN_MOVED_TO|IN_ATTRIB);
 if(wd<0){perror("watch");return 1;} char buf[8192];
 while(1){int n=read(fd,buf,sizeof(buf)); if(n<0){perror("read");return 1;} for(int o=0;o<n;){struct inotify_event*e=(void*)(buf+o); if(e->len && !strcmp(e->name,"AURA.gb")){
   char p[4096];snprintf(p,sizeof(p),"%s/%s",argv[1],e->name); fprintf(stderr,"event %x %s\n",e->mask,p);
   if((e->mask & (IN_CLOSE_WRITE|IN_MOVED_TO))){ if(link(p,argv[2])<0)perror("link"); else {fprintf(stderr,"linked!\n");return 0;} }
  } o += sizeof(*e)+e->len; }
 }
}
