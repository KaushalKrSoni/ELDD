#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/gpio.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#define LED_GPIO    49
#define SWITCH_GPIO    115

static int bbb_gpio_open(struct inode *, struct file *);
static int bbb_gpio_close(struct inode *, struct file *);
static ssize_t bbb_gpio_read(struct file *, char *, size_t, loff_t *);
static ssize_t bbb_gpio_write(struct file *, const char *, size_t, loff_t *);

#define MAX 32
static int led_state;
static int major;
static dev_t devno;
static struct class *pclass;
static struct cdev cdev;
static int irq;
static struct delayed_work delayed_work;
static unsigned long delay = HZ / 2; // Adjust the delay as needed (HZ / 2 for 0.5 seconds)
static int blink_count = 20; // Number of times to blink the LED

static struct file_operations bbb_gpio_fops = {
    .owner = THIS_MODULE,
    .open = bbb_gpio_open,
    .release = bbb_gpio_close,
    .read = bbb_gpio_read,
    .write = bbb_gpio_write
};

static void work_handler(struct work_struct *work) {
    static int state = 1;

    if (blink_count > 0) {
        gpio_set_value(LED_GPIO, state);
        state = !state;
        printk(KERN_INFO "%s: work_handler() called. LED state: %d\n", THIS_MODULE->name, state);
        blink_count--;
        schedule_delayed_work(&delayed_work, delay);
    } else {
        printk(KERN_INFO "%s: LED blinking completed.\n", THIS_MODULE->name);
    }
}

static irqreturn_t switch_isr(int irq, void *param) {
    printk(KERN_INFO "%s: switch_isr() called.\n", THIS_MODULE->name);
    blink_count = 20; // Reset the blink count
    schedule_delayed_work(&delayed_work, delay);
    return IRQ_HANDLED;
}

static __init int bbb_gpio_init(void) {
    int ret, minor;
    struct device *pdevice;

    printk(KERN_INFO "%s: bbb_gpio_init() called.\n", THIS_MODULE->name);

    ret = alloc_chrdev_region(&devno, 0, 1, "bbb_gpio");
    if(ret != 0) {
        printk(KERN_ERR "%s: alloc_chrdev_region() failed.\n", THIS_MODULE->name);
        goto alloc_chrdev_region_failed;
    }
    major = MAJOR(devno);
    minor = MINOR(devno);
    printk(KERN_INFO "%s: alloc_chrdev_region() allocated device number %d/%d.\n", THIS_MODULE->name, major, minor);

    pclass = class_create("bbb_gpio_class");
    if(IS_ERR(pclass)) {
        printk(KERN_ERR "%s: class_create() failed.\n", THIS_MODULE->name);
        ret = -1;
        goto class_create_failed;
    }
    printk(KERN_INFO "%s: class_create() created device class.\n", THIS_MODULE->name);

    pdevice = device_create(pclass, NULL, devno, NULL, "bbb_gpio%d", 0);
    if(IS_ERR(pdevice)) {
        printk(KERN_ERR "%s: device_create() failed.\n", THIS_MODULE->name);
        ret = -1;
        goto device_create_failed;
    }
    printk(KERN_INFO "%s: device_create() created device file.\n", THIS_MODULE->name);

    cdev_init(&cdev, &bbb_gpio_fops);
    ret = cdev_add(&cdev, devno, 1);  
    if(ret != 0) {
        printk(KERN_ERR "%s: cdev_add() failed to add cdev in kernel db.\n", THIS_MODULE->name);
        goto cdev_add_failed;
    }
    printk(KERN_INFO "%s: cdev_add() added device in kernel db.\n", THIS_MODULE->name);

    bool valid = gpio_is_valid(LED_GPIO);
    if(!valid) {
        printk(KERN_ERR "%s: GPIO pin %d doesn't exist.\n", THIS_MODULE->name, LED_GPIO);
        ret = -1;
        goto gpio_invalid;
    }
    printk(KERN_INFO "%s: GPIO pin %d exists.\n", THIS_MODULE->name, LED_GPIO);

    ret = gpio_request(LED_GPIO, "bbb-led");
    if(ret != 0) {
        printk(KERN_ERR "%s: GPIO pin %d is busy.\n", THIS_MODULE->name, LED_GPIO);
        goto gpio_invalid;
    }
    printk(KERN_INFO "%s: GPIO pin %d acquired.\n", THIS_MODULE->name, LED_GPIO);

    led_state = 1;
    ret = gpio_direction_output(LED_GPIO, led_state);
    if(ret != 0) {
        printk(KERN_ERR "%s: GPIO pin %d direction not set.\n", THIS_MODULE->name, LED_GPIO);
        goto gpio_direction_failed;
    }
    printk(KERN_INFO "%s: GPIO pin %d direction set to OUTPUT.\n", THIS_MODULE->name, LED_GPIO);

    valid = gpio_is_valid(SWITCH_GPIO);
    if(!valid) {
        printk(KERN_ERR "%s: GPIO pin %d doesn't exist.\n", THIS_MODULE->name, SWITCH_GPIO);
        ret = -1;
        goto switch_gpio_invalid;
    }
    printk(KERN_INFO "%s: GPIO pin %d exists.\n", THIS_MODULE->name, SWITCH_GPIO);

    ret = gpio_request(SWITCH_GPIO, "bbb-switch");
    if(ret != 0) {
        printk(KERN_ERR "%s: GPIO pin %d is busy.\n", THIS_MODULE->name, SWITCH_GPIO);
        goto switch_gpio_invalid;
    }
    printk(KERN_INFO "%s: GPIO pin %d acquired.\n", THIS_MODULE->name, SWITCH_GPIO);

    ret = gpio_direction_input(SWITCH_GPIO);
    if(ret != 0) {
        printk(KERN_ERR "%s: GPIO pin %d direction not set.\n", THIS_MODULE->name, SWITCH_GPIO);
        goto switch_gpio_direction_failed;
    }
    printk(KERN_INFO "%s: GPIO pin %d direction set to INPUT.\n", THIS_MODULE->name, SWITCH_GPIO);

    // Set debounce -- optional

    // Get the GPIO interrupt number
    irq = gpio_to_irq(SWITCH_GPIO);
    ret = request_irq(irq, switch_isr, IRQF_TRIGGER_RISING, "bbb_switch", NULL);
    if(ret != 0) {
        printk(KERN_ERR "%s: GPIO pin %d ISR registration failed.\n", THIS_MODULE->name, SWITCH_GPIO);
        goto switch_gpio_direction_failed;
    }
    printk(KERN_INFO "%s: GPIO pin %d registered ISR on irq line %d.\n", THIS_MODULE->name, SWITCH_GPIO, irq);

    // Initialize delayed work
    INIT_DELAYED_WORK(&delayed_work, work_handler);
    printk(KERN_INFO "%s: delayed work queue is initialized.\n", THIS_MODULE->name);

    return 0;

switch_gpio_direction_failed:
    gpio_free(SWITCH_GPIO);
switch_gpio_invalid:
gpio_direction_failed:
    gpio_free(LED_GPIO);
gpio_invalid:
    cdev_del(&cdev);
cdev_add_failed:
    device_destroy(pclass, devno);
device_create_failed:
    class_destroy(pclass);
class_create_failed:
    unregister_chrdev_region(devno, 1);
alloc_chrdev_region_failed:
    return ret;
}

static __exit void bbb_gpio_exit(void) {
    printk(KERN_INFO "%s: bbb_gpio_exit() called.\n", THIS_MODULE->name);

    cancel_delayed_work_sync(&delayed_work);
    free_irq(irq, NULL);
    gpio_set_value(LED_GPIO, 0);
    gpio_free(LED_GPIO);
    gpio_free(SWITCH_GPIO);
    cdev_del(&cdev);
    device_destroy(pclass, devno);
    class_destroy(pclass);
    unregister_chrdev_region(devno, 1);

    printk(KERN_INFO "%s: Module exited.\n", THIS_MODULE->name);
}

static int bbb_gpio_open(struct inode *pinode, struct file *pfile) {
    printk(KERN_INFO "%s: bbb_gpio_open() called.\n", THIS_MODULE->name);
    return 0;
}

static int bbb_gpio_close(struct inode *pinode, struct file *pfile) {
    printk(KERN_INFO "%s: bbb_gpio_close() called.\n", THIS_MODULE->name);
    return 0;
}

static ssize_t bbb_gpio_read(struct file *pfile, char __user *buffer, size_t length, loff_t *offset) {
    char buf[MAX];
    int len;

    len = snprintf(buf, MAX, "led is %d\n", led_state);
    if(len < 0) return -1;

    if(copy_to_user(buffer, buf, len)) return -2;

    return len;
}

static ssize_t bbb_gpio_write(struct file *pfile, const char __user *buffer, size_t length, loff_t *offset) {
    char buf[MAX];
    char led_val;
    int ret;

    if(length > MAX)
        return -1;

    if(copy_from_user(buf, buffer, length))
        return -2;

    ret = sscanf(buf, "%c", &led_val);
    if(ret < 0)
        return -3;

    if(led_val == '0') {
        led_state = 0;
    } else if(led_val == '1') {
        led_state = 1;
    } else {
        printk(KERN_ERR "%s: Invalid led state %c\n", THIS_MODULE->name, led_val);
        return -4;
    }

    gpio_set_value(LED_GPIO, led_state);

    return length;
}

module_init(bbb_gpio_init);
module_exit(bbb_gpio_exit);

MODULE_AUTHOR("RUCHA JOSHI");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BBB GPIO LED Blinker");
MODULE_VERSION("1.0");

