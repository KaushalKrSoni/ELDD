#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kfifo.h>
#include <linux/slab.h>
#include <linux/wait.h>

static int pchar_open(struct inode *, struct file *);
static int pchar_close(struct inode *, struct file *);
static ssize_t pchar_read(struct file *, char *, size_t, loff_t *);
static ssize_t pchar_write(struct file *, const char *, size_t, loff_t *);

#define MAX 32

// Device private struct
struct pchar_device {
    struct kfifo buf;
    dev_t devno;
    struct cdev cdev;
    wait_queue_head_t read_queue;
    wait_queue_head_t write_queue;
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
    int ret, i;
    struct device *pdevice;
    dev_t devno;

    printk(KERN_INFO "%s: pchar_init() called.\n", THIS_MODULE->name);

    devices = kmalloc_array(devcnt, sizeof(struct pchar_device), GFP_KERNEL);
    if (!devices) {
        ret = -ENOMEM;
        printk(KERN_ERR "%s: kmalloc() failed to allocate devices private struct memory.\n", THIS_MODULE->name);
        goto devices_kmalloc_failed;
    }
    printk(KERN_INFO "%s: kmalloc() allocated devices private struct memory.\n", THIS_MODULE->name);

    for (i = 0; i < devcnt; i++) {
        ret = kfifo_alloc(&devices[i].buf, MAX, GFP_KERNEL);
        if (ret) {
            printk(KERN_ERR "%s: kfifo_alloc() failed for device %d.\n", THIS_MODULE->name, i);
            goto kfifo_alloc_failed;
        }
        init_waitqueue_head(&devices[i].read_queue);
        init_waitqueue_head(&devices[i].write_queue);
        printk(KERN_INFO "%s: kfifo_alloc() and wait queues initialized for device %d.\n", THIS_MODULE->name, i);
    }

    ret = alloc_chrdev_region(&devno, 0, devcnt, "pchar");
    if (ret) {
        printk(KERN_ERR "%s: alloc_chrdev_region() failed.\n", THIS_MODULE->name);
        goto alloc_chrdev_region_failed;
    }
    major = MAJOR(devno);
    printk(KERN_INFO "%s: alloc_chrdev_region() allocated device number %d.\n", THIS_MODULE->name, major);

    pclass = class_create("pchar_class");
    if (IS_ERR(pclass)) {
        printk(KERN_ERR "%s: class_create() failed.\n", THIS_MODULE->name);
        ret = PTR_ERR(pclass);
        goto class_create_failed;
    }
    printk(KERN_INFO "%s: class_create() created device class.\n", THIS_MODULE->name);

    for (i = 0; i < devcnt; i++) {
        devno = MKDEV(major, i);
        pdevice = device_create(pclass, NULL, devno, NULL, "pchar%d", i);
        if (IS_ERR(pdevice)) {
            printk(KERN_ERR "%s: device_create() failed for device %d.\n", THIS_MODULE->name, i);
            ret = PTR_ERR(pdevice);
            goto device_create_failed;
        }
        devices[i].devno = devno;
        cdev_init(&devices[i].cdev, &pchar_fops);
        ret = cdev_add(&devices[i].cdev, devno, 1);
        if (ret) {
            printk(KERN_ERR "%s: cdev_add() failed to add cdev %d in kernel db.\n", THIS_MODULE->name, i);
            goto cdev_add_failed;
        }
    }
    printk(KERN_INFO "%s: cdev_add() added devices in kernel db.\n", THIS_MODULE->name);

    return 0;

cdev_add_failed:
    for (i = i - 1; i >= 0; i--)
        cdev_del(&devices[i].cdev);
device_create_failed:
    for (i = 0; i < devcnt; i++) {
        devno = MKDEV(major, i);
        device_destroy(pclass, devno);
    }
    class_destroy(pclass);
class_create_failed:
    unregister_chrdev_region(devno, devcnt);
alloc_chrdev_region_failed:
    for (i = 0; i < devcnt; i++)
        kfifo_free(&devices[i].buf);
    kfree(devices);
devices_kmalloc_failed:
    return ret;

kfifo_alloc_failed:
    for (i = i - 1; i >= 0; i--)
        kfifo_free(&devices[i].buf);
    kfree(devices);
    return ret;
}

static __exit void pchar_exit(void) {
    int i;
    printk(KERN_INFO "%s: pchar_exit() called.\n", THIS_MODULE->name);
    for (i = devcnt - 1; i >= 0; i--) {
        cdev_del(&devices[i].cdev);
        device_destroy(pclass, devices[i].devno);
        kfifo_free(&devices[i].buf);
    }
    class_destroy(pclass);
    unregister_chrdev_region(MKDEV(major, 0), devcnt);
    kfree(devices);
    printk(KERN_INFO "%s: Unloaded module and cleaned up resources.\n", THIS_MODULE->name);
}

static int pchar_open(struct inode *pinode, struct file *pfile) {
    struct pchar_device *pdev = container_of(pinode->i_cdev, struct pchar_device, cdev);
    pfile->private_data = pdev;
    printk(KERN_INFO "%s: pchar_open() called.\n", THIS_MODULE->name);
    return 0;
}

static int pchar_close(struct inode *pinode, struct file *pfile) {
    printk(KERN_INFO "%s: pchar_close() called.\n", THIS_MODULE->name);
    return 0;
}

static ssize_t pchar_read(struct file *pfile, char *ubuf, size_t size, loff_t *poffset) {
    struct pchar_device *pdev = pfile->private_data;
    int ret, nbytes = 0;

    printk(KERN_INFO "%s: pchar_read() called.\n", THIS_MODULE->name);
    
    // Wait until there is data to read
    ret = wait_event_interruptible(pdev->read_queue, !kfifo_is_empty(&pdev->buf));
    if (ret) {
        printk(KERN_ERR "%s: pchar_read() interrupted while waiting.\n", THIS_MODULE->name);
        return ret;
    }

    ret = kfifo_to_user(&pdev->buf, ubuf, size, &nbytes);
    if (ret) {
        printk(KERN_ERR "%s: pchar_read() failed to copy data to user space.\n", THIS_MODULE->name);
        return ret;
    }

    printk(KERN_INFO "%s: pchar_read() copied %d bytes to user space.\n", THIS_MODULE->name, nbytes);

    // Wake up writers if there is space available
    if (!kfifo_is_full(&pdev->buf)) {
        wake_up_interruptible(&pdev->write_queue);
    }

    return nbytes;
}

static ssize_t pchar_write(struct file *pfile, const char *ubuf, size_t size, loff_t *poffset) {
    struct pchar_device *pdev = pfile->private_data;
    int ret, nbytes = size;

    printk(KERN_INFO "%s: pchar_write() called.\n", THIS_MODULE->name);
    
    // Wait until there is space to write
    ret = wait_event_interruptible(pdev->write_queue, !kfifo_is_full(&pdev->buf));
    if (ret) {
        printk(KERN_ERR "%s: pchar_write() interrupted while waiting.\n", THIS_MODULE->name);
        return ret;
    }

    ret = kfifo_from_user(&pdev->buf, ubuf, size, &nbytes);
    if (ret) {
        printk(KERN_ERR "%s: pchar_write() failed to copy data from user space.\n", THIS_MODULE->name);
        return ret;
    }

    printk(KERN_INFO "%s: pchar_write() copied %d bytes from user space.\n", THIS_MODULE->name, nbytes);

    // Wake up readers if there is data available
    if (!kfifo_is_empty(&pdev->buf)) {
        wake_up_interruptible(&pdev->read_queue);
    }

    return nbytes;
}

module_init(pchar_init);
module_exit(pchar_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nilesh Ghule <nilesh@sunbeaminfo.com>");
MODULE_DESCRIPTION("Simple pchar driver with kfifo and wait queue.");

