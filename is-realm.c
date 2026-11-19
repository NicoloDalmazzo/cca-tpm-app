#include <stdio.h>       
#include <fcntl.h>       
#include <unistd.h>      
#include <sys/ioctl.h>
#include <linux/ioctl.h>

#define IOC_IS_REALM _IOR('R', 1, int)

int main()
{
    int fd = open("/dev/is-realm", O_RDONLY);
    int is_realm;
    
    if ( fd < 0 || ioctl(fd, IOC_IS_REALM, &is_realm) < 0 )
        return 2;
    
    close(fd);

    return is_realm ? 0 : 1;
}


