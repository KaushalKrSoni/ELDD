#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kfifo.h>
#include <linux/slab.h>

static int pchar_open(struct inode *, struct file *);
static int pchar_close(struct inode *, struct file *);
static ssize_t pchar_read(struct file *, char *, size_t, loff_t *);
static ssize_t pchar_write(struct file *, const char *, size_t, loff_t *);

#define MAX 32

// device private struct
struct pchar_device {
    struct kfifo buf;
    dev_t devno;
    struct cdev cdev;
};

static int major;
static struct class *pclass;
static int devcnt = 3;
struct pchar_device *devices;

static struct file_operations pchar_fops = {
    .owner = THIS_MODULE,
    .open = pchar_open,
    .release = pchar_close,
    .read = pchar_read,
    .write = pchar_write
};

static __init int pchar_init(void) {
    int ret, minor, i;
    struct device *pdevice;
    dev_t devno;

    printk(KERN_INFO "%s: pchar_init() called.\n", THIS_MODULE->name);

    devices = (struct pchar_device*)kmalloc(devcnt * sizeof(struct pchar_device), GFP_KERNEL);
    if(devices == NULL) {
        ret = -ENOMEM;
        printk(KERN_ERR "%s: kmalloc() failed to allocate devices private struct memory.\n", THIS_MODULE->name);
        goto devices_kmalloc_failed;
    }
    printk(KERN_INFO "%s: kmalloc() allocated devices private struct memory.\n", THIS_MODULE->name);

    for(i=0; i<devcnt; i++) {
        ret = kfifo_alloc(&devices[i].buf, MAX, GFP_KERNEL);
        if(ret != 0) {
            printk(KERN_ERR "%s: kfifo_alloc() failed for device %d.\n", THIS_MODULE->name, i);
            goto kfifo_alloc_failed;
        }
        printk(KERN_ERR "%s: kfifo_alloc() successfully created %d devices.\n", THIS_MODULE->name, devcnt);
    }

    ret = alloc_chrdev_region(&devno, 0, devcnt, "pchar");
    if(ret != 0) {
        printk(KERN_ERR "%s: alloc_chrdev_region() failed.\n", THIS_MODULE->name);
        goto alloc_chrdev_region_failed;
    }
    major = MAJOR(devno);
    minor = MINOR(devno);
    printk(KERN_INFO "%s: alloc_chrdev_region() allocated device number %d/%d.\n", THIS_MODULE->name, major, minor);

    pclass = class_create("pchar_class");
    if(IS_ERR(pclass)) {
        printk(KERN_ERR "%s: class_create() failed.\n", THIS_MODULE->name);
        ret = -1;
        goto class_create_failed;
    }
    printk(KERN_INFO "%s: class_create() created device class.\n", THIS_MODULE->name);

    for(i=0; i<devcnt; i++) {
        devno = MKDEV(major, i);
        pdevice = device_create(pclass, NULL, devno, NULL, "pchar%d", i);
        if(IS_ERR(pdevice)) {
            printk(KERN_ERR "%s: device_create() failed for device  %d.\n", THIS_MODULE->name, i);
            ret = -1;
            goto device_create_failed;
        }
    }
    printk(KERN_INFO "%s: device_create() created device files.\n", THIS_MODULE->name);

    for(i=0; i<devcnt; i++) {
        devno = MKDEV(major, i);
        devices[i].devno = devno;
        cdev_init(&devices[i].cdev, &pchar_fops);
        ret = cdev_add(&devices[i].cdev, devno, 1);  
        if(ret != 0) {
            printk(KERN_ERR "%s: cdev_add() failed to add cdev %d in kernel db.\n", THIS_MODULE->name, i);
            goto cdev_add_failed;
        }
    }
    printk(KERN_INFO "%s: cdev_add() added devices in kernel db.\n", THIS_MODULE->name);

    return 0;
cdev_add_failed:
    for(i=i-1; i>=0; i--)
        cdev_del(&devices[i].cdev);
    i = devcnt;
device_create_failed:
    for(i=i-1; i>=0; i--) {
        devno = MKDEV(major, i);
        device_destroy(pclass, devno);
    }
    class_destroy(pclass);
class_create_failed:
    unregister_chrdev_region(devno, 1);
alloc_chrdev_region_failed:
    i=devcnt;
kfifo_alloc_failed:
    for(i=i-1; i>=0; i--)
        kfifo_free(&devices[i].buf);
    kfree(devices);
devices_kmalloc_failed:
    return ret;
}

static __exit void pchar_exit(void) {
    int i;
    dev_t devno;
    printk(KERN_INFO "%s: pchar_exit() called.\n", THIS_MODULE->name);
    for(i=devcnt-1; i>=0; i--)
        cdev_del(&devices[i].cdev);
    printk(KERN_INFO "%s: cdev_del() removed devices from kernel db.\n", THIS_MODULE->name);
    for(i=devcnt-1; i>=0; i--) {
        devno = MKDEV(major, i);
        device_destroy(pclass, devno);
    }
    printk(KERN_INFO "%s: device_destroy() destroyed device files.\n", THIS_MODULE->name);
    class_destroy(pclass);
    printk(KERN_INFO "%s: class_destroy() destroyed device class.\n", THIS_MODULE->name);
    unregister_chrdev_region(devno, 1);
    printk(KERN_INFO "%s: unregister_chrdev_region() released device number.\n", THIS_MODULE->name);
    for(i=devcnt-1; i>=0; i--)
        kfifo_free(&devices[i].buf);
    printk(KERN_INFO "%s: kfifo_free() destroyed devices.\n", THIS_MODULE->name);
    kfree(devices);
    printk(KERN_INFO "%s: kfree() released devices private struct memory.\n", THIS_MODULE->name);
}


static int pchar_open(struct inode *pinode, struct file *pfile) {
    printk(KERN_INFO "%s: pchar_open() called.\n", THIS_MODULE->name);
    struct pchar_device *pdev =
    container_of(pinode->i_cdev, struct pchar_device, cdev);
    pfile->private_data = pdev;
    return 0;
}

static int pchar_close(struct inode *pinode, struct file *pfile) {
    printk(KERN_INFO "%s: pchar_close() called.\n", THIS_MODULE->name);
    struct pchar_device *pdev = (struct pchar_device *)pfile->private_data;
    (void)pdev;
    return 0;
}

static ssize_t pchar_read(struct file *pfile, char *ubuf, size_t size, loff_t *poffset) {
    int nbytes=0, ret;
    printk(KERN_INFO "%s: pchar_read() called.\n", THIS_MODULE->name);
    struct pchar_device *pdev = (struct pchar_device *)pfile->private_data;
    ret = kfifo_to_user(&pdev->buf, ubuf, size, &nbytes);
    if(ret < 0) {
        printk(KERN_ERR "%s: pchar_read() failed to copy data from kernel space using kfifo_to_user().\n", THIS_MODULE->name);
        return ret;     
    }
    printk(KERN_INFO "%s: pchar_read() copied %d bytes to user space.\n", THIS_MODULE->name, nbytes);
    return nbytes;
}

static ssize_t pchar_write(struct file *pfile, const char *ubuf, size_t size, loff_t *poffset) {
    int nbytes=size, ret;
    printk(KERN_INFO "%s: pchar_write() called.\n", THIS_MODULE->name);
    struct pchar_device *pdev = (struct pchar_device *)pfile->private_data;
    ret = kfifo_from_user(&pdev->buf, ubuf, size, &nbytes);
    if(ret < 0) {
        printk(KERN_ERR "%s: pchar_write() failed to copy data in kernel space using kfifo_from_user().\n", THIS_MODULE->name);
        return ret;     
    }
    printk(KERN_INFO "%s: pchar_write() copied %d bytes from user space.\n", THIS_MODULE->name, nbytes);
    return nbytes;
}

module_init(pchar_init);
module_exit(pchar_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nilesh Ghule <nilesh@sunbeaminfo.com>");
MODULE_DESCRIPTION("Simple pchar driver with kfifo as device.");

