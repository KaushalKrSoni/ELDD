#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include "pchar_ioctl.h"

int main(int argc, char *argv[])
{
    int fd, ret;
    if (argc != 2)
    {
        printf("invalid usage.\n");
        printf("usage1: %s clear\n", argv[0]);
        printf("usage2: %s info\n", argv[0]);
        printf("usage3: %s resize\n", argv[0]);
        _exit(2);
    }

    fd = open("/dev/pchar0", O_RDWR);
    if (fd < 0)
    {
        perror("open() failed");
        _exit(1);
    }

    if (strcmp(argv[1], "clear") == 0)
    {
        // fifo clear
        ret = ioctl(fd, FIFO_CLEAR);
        if (ret != 0)
            perror("ioctl(FIFO_CLEAR) failed");
        else
            printf("fifo cleared.\n");
    }
    else if (strcmp(argv[1], "info") == 0)
    {
        // fifo get info
        info_t info;
        ret = ioctl(fd, FIFO_INFO, &info);
        if (ret != 0)
            perror("ioctl(FIFO_INFO) failed");
        else
            printf("fifo info: size=%d, filled=%d, empty=%d.\n", info.size, info.len, info.avail);
    }
    else if (strcmp(argv[1], "resize") == 0)
    {
        // fifo resize
        info_t info;
        ret = ioctl(fd, FIFO_INFO, &info);
        if (ret != 0)
        {
            perror("ioctl(FIFO_INFO) failed");
            close(fd);
            return 1;
        }

        ret = ioctl(fd, FIFO_RESIZE, info.len);
        if (ret != 0)
            perror("ioctl(FIFO_RESIZE) failed");
        else
            printf("fifo resized to %d.\n", info.len);
    }
    else
    {
        printf("invalid usage.\n");
        printf("usage1: %s clear\n", argv[0]);
        printf("usage2: %s info\n", argv[0]);
        printf("usage3: %s resize\n", argv[0]);
    }

    close(fd);
    return 0;
}

