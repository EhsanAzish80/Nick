// Local Test A only. Opens synthetic credential-shaped paths below a private,
// nonce-marked directory. No network, arbitrary paths, or credential contents.
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
static int rootfd;
static double deadline;
static double per_worker_rate;
static _Atomic unsigned long opened, denied, failed;
static const char *paths[] = {"Cookies", "Library/Keychains/synthetic.keychain-db", ".ssh/id_synthetic"};
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
static int private_directory(int dir) {struct stat s;return fstat(dir,&s)==0 && S_ISDIR(s.st_mode) && s.st_uid==geteuid() && (s.st_mode&077)==0;}
static int validate_root(const char *nonce) {
    char marker[128]={0};
    if (!private_directory(rootfd)) return 0;
    int fd=openat(rootfd,".nick-credential-diagnostic",O_RDONLY|O_NOFOLLOW);
    if(fd<0)return 0;
    ssize_t n=read(fd,marker,sizeof(marker)-1);close(fd);
    if(n<1 || (size_t)n!=strlen(nonce) || memcmp(marker,nonce,(size_t)n))return 0;
    int library=openat(rootfd,"Library",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    int ssh=openat(rootfd,".ssh",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(library<0 || ssh<0){if(library>=0)close(library);if(ssh>=0)close(ssh);return 0;}
    int keys=openat(library,"Keychains",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    int valid=private_directory(library) && private_directory(ssh) && keys>=0 && private_directory(keys);
    close(library);close(ssh);if(keys>=0)close(keys);
    return valid;
}
static void *run(void *argument) {
    unsigned long count=(unsigned long)argument;
    double started=now();unsigned long attempts=0;
    while(now()<deadline) {
        int fd=openat(rootfd,paths[count++%3],O_RDONLY|O_NOFOLLOW);
        if(fd>=0){atomic_fetch_add(&opened,1);close(fd);}
        else if(errno==EPERM || errno==EACCES)atomic_fetch_add(&denied,1);
        else atomic_fetch_add(&failed,1);
        attempts++;
        double delay=started+attempts/per_worker_rate-now();
        if(delay>0){struct timespec t={(time_t)delay,(long)((delay-(time_t)delay)*1e9)};nanosleep(&t,NULL);}
    }
    return NULL;
}
int main(int argc,char **argv) {
    if(argc!=6 || strlen(argv[2])<16 || strlen(argv[2])>=128)return 64;
    int duration=atoi(argv[3]),threads=atoi(argv[4]),rate=atoi(argv[5]);
    if(duration<1 || duration>1800 || threads<1 || threads>32 || rate<1 || rate>10000)return 64;
    rootfd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if(rootfd<0 || !validate_root(argv[2]))return 65;
    per_worker_rate=(double)rate/threads;deadline=now()+duration;
    pthread_t workers[32];int created=0;
    for(int i=0;i<threads;i++){if(pthread_create(&workers[i],NULL,run,(void *)(unsigned long)i))break;created++;}
    for(int i=0;i<created;i++)pthread_join(workers[i],NULL);
    printf("{\"opened\":%lu,\"denied\":%lu,\"otherErrors\":%lu,\"threads\":%d,\"seconds\":%d}\n",atomic_load(&opened),atomic_load(&denied),atomic_load(&failed),created,duration);
    close(rootfd);return created==threads && !atomic_load(&failed)?0:1;
}
