#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "spinlock.h"
#include "osprd.h"
#include <linux/string.h>

/* The size of an OSPRD sector. */
#define SECTOR_SIZE	512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED	0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE: Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("BaixiaoHuang_and_JiayiLu");

#define OSPRD_MAJOR	222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);


/* The internal representation of our device. */
typedef struct osprd_info {
	uint8_t *data;                  // The data array. Its size is
	                                // (nsectors * SECTOR_SIZE) bytes.

	osp_spinlock_t mutex;           // Mutex for synchronizing access to
					// this block device

	unsigned ticket_head;		// Currently running ticket for
					// the device lock

	unsigned ticket_tail;		// Next available ticket for
					// the device lock

	wait_queue_head_t blockq;       // Wait queue for tasks blocked on
					// the device lock

	/* HINT: You may want to add additional fields to help
	         in detecting deadlock. */
//////////////////////////////////////////////////////////////////////
    int num_reader;
    int num_writer;
    unsigned* invalid_tickets_array;
    unsigned int num_invalid_tikets;
    pid_t current_popular_writer;
    
    struct notification_list* notifi_list;
    struct notification_list* notifi_list_tail;
//////////////////////////////////////////////////////////////////////

	// The following elements are used internally; you don't need
	// to understand them.
	struct request_queue *queue;    // The device request queue.
	spinlock_t qlock;		// Used internally for mutual
	                                //   exclusion in the 'queue'.
	struct gendisk *gd;             // The generic disk.
} osprd_info_t;

//////////////////////////////////////////////////////////////////////
//notification structure//
//////////////////////////
typedef struct notification_list
{
    pid_t waiter_pid;
    int change;
    int start;
    int end;
    struct notification_list *next;
} notification_list_t;
//////////////////////////////////////////////////////////////////////

#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];


// Declare useful helper functions
char* parseNotifiArg(char* arg, int *start_ptr, int *end_ptr);
/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
			       void (*callback)(struct file *filp,
						osprd_info_t *user_data),
			       osprd_info_t *user_data);


/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
	if (!blk_fs_request(req)) {
		end_request(req, 0);
		return;
	}
	// Your code here.
    unsigned long offset = req->sector*SECTOR_SIZE;
    unsigned long dataSize = req->current_nr_sectors*SECTOR_SIZE;
    
    if (rq_data_dir(req)==READ) {
        osp_spin_lock(&(d->mutex));
        memcpy(req->buffer, d->data+offset, dataSize);
        osp_spin_unlock(&(d->mutex));
    }else if (rq_data_dir(req)==WRITE){
        osp_spin_lock(&(d->mutex));
        memcpy(d->data+offset, req->buffer, dataSize);
        osp_spin_unlock(&(d->mutex));
    }else{
        end_request(req,1);
    }
    
    
    
	//eprintk("Should process request...\n");

	end_request(req, 1);
}


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
	// Always set the O_SYNC flag. That way, we will get writes immediately
	// instead of waiting for them to get through write-back caches.
	filp->f_flags |= O_SYNC;
	return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{
	if (filp) {
		osprd_info_t *d = file2osprd(filp);
		int filp_writable = filp->f_mode & FMODE_WRITE;

		// EXERCISE: If the user closes a ramdisk file that holds
		// a lock, release the lock.  Also wake up blocked processes
		// as appropriate.

		// Your code here.
        
        //first thing first, lock the mutex
        osp_spin_lock(&(d->mutex));
        if (filp_writable) {  //fire the writer
            if (filp->f_flags&F_OSPRD_LOCKED && d->num_writer!=0) {
                filp->f_flags &= ~F_OSPRD_LOCKED;
            }
            d->num_writer=0;
            d->current_popular_writer=-1;
        }else{               //a reader is tired of reading
            if (filp->f_flags && d->num_reader!=0) {
                d->num_reader--;
            }
            if (d->num_reader==0) {  //we can unlock if no reader is interested in reading
                filp->f_flags &= ~F_OSPRD_LOCKED;
            }
        }
        wake_up_all(&(d->blockq));
        osp_spin_unlock(&(d->mutex));
		// This line avoids compiler warnings; you may remove it.
		(void) filp_writable, (void) d;

	}

	return 0;
}


/*
 * osprd_lock
 */

/*
 * osprd_ioctl(inode, filp, cmd, arg)
 *   Called to perform an ioctl on the named file.
 */
int osprd_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	osprd_info_t *d = file2osprd(filp);	// device info
	int r = 0;			// return value: initially 0

	// is file open for writing?
	int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

	// This line avoids compiler warnings; you may remove it.
	(void) filp_writable, (void) d;

	// Set 'r' to the ioctl's return value: 0 on success, negative on error

	if (cmd == OSPRDIOCACQUIRE) {

		// Your code here (instead of the next two lines).
        
        //buy a ticket and wait in line
        osp_spin_lock(&(d->mutex));
        unsigned my_ticket = d->ticket_head;
        d->ticket_head++;
        osp_spin_unlock(&(d->mutex));
        if (filp_writable) {        //trying to obtain write lock
            if (wait_event_interruptible(d->blockq, d->ticket_tail==my_ticket&&d->num_reader==0 && d->num_writer==0)==-ERESTARTSYS) {
                osp_spin_lock(&(d->mutex));
                if (d->ticket_tail==my_ticket) {
                    d->ticket_tail++;
                }
                else{
                    d->invalid_tickets_array[d->num_invalid_tikets++]=my_ticket;
                    d->num_invalid_tikets++;
                }
                osp_spin_unlock(&(d->mutex));
                return -ERESTARTSYS;
            }
            //get your write lock here, good luck writing!
            //eprintk("I got write lock!\n");
            osp_spin_lock(&(d->mutex));
            d->num_writer++;
            d->current_popular_writer = current->pid;
            filp->f_flags |= F_OSPRD_LOCKED;
            osp_spin_unlock(&(d->mutex));
        }else{                      //trying to obtain read lock
            if (wait_event_interruptible(d->blockq, (d->ticket_tail==my_ticket && d->num_writer==0))==-ERESTARTSYS) {
                osp_spin_lock(&(d->mutex));
                if (d->ticket_tail==my_ticket) {
                    d->ticket_tail++;
                }
                else{
                    d->invalid_tickets_array[d->num_invalid_tikets++]=my_ticket;
                    d->num_invalid_tikets++;
                }
                osp_spin_unlock(&(d->mutex));
                return -ERESTARTSYS;
            }
            //get your read lock here, good luck reading!
            osp_spin_lock(&(d->mutex));
            d->num_reader++;
            filp->f_flags |= F_OSPRD_LOCKED;
            osp_spin_unlock(&(d->mutex));
        }
        //next in line please! But we need to check if next guy is still alive :-)
        osp_spin_lock(&(d->mutex));
        d->ticket_tail++;
        int i=0;
        for (; i<d->num_invalid_tikets; i++) {
            if (d->invalid_tickets_array[i]==d->ticket_tail) {
                d->ticket_tail++;
                d->invalid_tickets_array[i] = d->invalid_tickets_array[d->num_invalid_tikets];
                d->num_invalid_tikets--;
                i=0;
            }
        }
        osp_spin_unlock(&(d->mutex));
        r=0;

	} else if (cmd == OSPRDIOCTRYACQUIRE) {
		// Your code here (instead of the next two lines).
        osp_spin_lock(&(d->mutex));
        if (filp_writable) {  //a writer wants to publish his/her book!
            if (d->num_reader==0 && d->num_writer==0) {
                //writer get the lock, good luck writing!
                d->num_writer++;
                d->current_popular_writer = current->pid;
                filp->f_flags |= F_OSPRD_LOCKED;
            }else{
                osp_spin_unlock(&(d->mutex));
                return -EBUSY;
            }
        }else{    //an avid reader is waiting for new book release!
            if (d->num_writer==0) {
                //reader grabs a book and run away
                d->num_reader++;
                filp->f_flags |= F_OSPRD_LOCKED;
            }else{
                osp_spin_unlock(&(d->mutex));
                return -EBUSY;
            }
        }
        osp_spin_unlock(&(d->mutex));
        r = 0;

	} else if (cmd == OSPRDIOCRELEASE) {
		// Your code here (instead of the next line).
        osp_spin_lock(&(d->mutex));
        if (!(filp->f_flags & F_OSPRD_LOCKED)) { //no lock flag
            return -EINVAL;
        }
        if (filp_writable) {    //fire all writers
            d->num_writer=0;
            filp->f_flags &= ~F_OSPRD_LOCKED;
        }else{                  //one reader quit reading
            d->num_reader--;
            if (d->num_reader==0) {
                filp->f_flags &= ~F_OSPRD_LOCKED;
            }
        }
        wake_up_all(&(d->blockq));
        osp_spin_unlock(&(d->mutex));
        r=0;
    } else if (cmd == OSPRDIOCGETNOTIFIED){
        int start=0, end=0;
        char* argument = (char*) arg;
        while (*argument!='\0') {
            struct notification_list * new_node = (struct notification_list*)kmalloc(sizeof(struct notification_list), GFP_ATOMIC);
            argument = parseNotifiArg(argument, &start, &end);
            new_node->change = 0;
            new_node->start = start;
            new_node->end = end;
            new_node->next = NULL;
            new_node->waiter_pid = current->pid;
            if (d->notifi_list==NULL) {
                d->notifi_list = new_node;
                d->notifi_list_tail = new_node;
            }else{
                d->notifi_list_tail->next = new_node;
                d->notifi_list_tail = new_node;
            }
        }
        struct notification_list * ptr = d->notifi_list;
        while (ptr!=NULL) {
            start = ptr->start;
            end = ptr->end;
            eprintk("process %d subscribe the notification: %d to %d\n", ptr->waiter_pid, start, end);
            ptr = ptr->next;
        }
    } else
		r = -ENOTTY; /* unknown command */
	return r;
}


// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
	/* Initialize the wait queue. */
	init_waitqueue_head(&d->blockq);
	osp_spin_lock_init(&d->mutex);
	d->ticket_head = d->ticket_tail = 0;
	/* Add code here if you add fields to osprd_info_t. */
    d->num_writer=0;
    d->num_reader=0;
    d->invalid_tickets_array = (unsigned*) kmalloc(1024*sizeof(unsigned), GFP_ATOMIC);
    d->num_invalid_tikets=0;
    d->current_popular_writer=-1;
    d->notifi_list = NULL;
    d->notifi_list_tail = NULL;
}

char* parseNotifiArg(char* arg, int *start_ptr, int *end_ptr)
{
    int getStart = 1;
    *start_ptr = 0;
    *end_ptr = 0;
    while (arg!=NULL && *arg!='\0') {
        if (*arg==':') {
            getStart=0;
        }else if(*arg==','){
            arg++;
            break;
        }else if(getStart == 1 && (int)*arg>=(int)'0' && (int)*arg<=(int)'9'){
            *start_ptr *= 10;
            *start_ptr += ((int)*arg - (int)'0');
        }else if(getStart == 0 && (int)*arg>=(int)'0' && (int)*arg<=(int)'9'){
            *end_ptr *= 10;
            *end_ptr += ((int)*arg - (int)'0');
        }
        arg++;
    }
    return arg;
}

/*****************************************************************************/
/*         THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE!          */
/*                                                                           */
/*****************************************************************************/

// Process a list of requests for a osprd_info_t.
// Calls osprd_process_request for each element of the queue.

static void osprd_process_request_queue(request_queue_t *q)
{
	osprd_info_t *d = (osprd_info_t *) q->queuedata;
	struct request *req;

	while ((req = elv_next_request(q)) != NULL)
		osprd_process_request(d, req);
}


// Some particularly horrible stuff to get around some Linux issues:
// the Linux block device interface doesn't let a block device find out
// which file has been closed.  We need this information.

static struct file_operations osprd_blk_fops;
static int (*blkdev_release)(struct inode *, struct file *);

static int _osprd_release(struct inode *inode, struct file *filp)
{
	if (file2osprd(filp))
		osprd_close_last(inode, filp);
	return (*blkdev_release)(inode, filp);
}

static int _osprd_open(struct inode *inode, struct file *filp)
{
	if (!osprd_blk_fops.open) {
		memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));
		blkdev_release = osprd_blk_fops.release;
		osprd_blk_fops.release = _osprd_release;
	}
	filp->f_op = &osprd_blk_fops;
	return osprd_open(inode, filp);
}


// The device operations structure.

static struct block_device_operations osprd_ops = {
	.owner = THIS_MODULE,
	.open = _osprd_open,
	// .release = osprd_release, // we must call our own release
	.ioctl = osprd_ioctl
};


// Given an open file, check whether that file corresponds to an OSP ramdisk.
// If so, return a pointer to the ramdisk's osprd_info_t.
// If not, return NULL.

static osprd_info_t *file2osprd(struct file *filp)
{
	if (filp) {
		struct inode *ino = filp->f_dentry->d_inode;
		if (ino->i_bdev
		    && ino->i_bdev->bd_disk
		    && ino->i_bdev->bd_disk->major == OSPRD_MAJOR
		    && ino->i_bdev->bd_disk->fops == &osprd_ops)
			return (osprd_info_t *) ino->i_bdev->bd_disk->private_data;
	}
	return NULL;
}


// Call the function 'callback' with data 'user_data' for each of 'task's
// open files.

static void for_each_open_file(struct task_struct *task,
		  void (*callback)(struct file *filp, osprd_info_t *user_data),
		  osprd_info_t *user_data)
{
	int fd;
	task_lock(task);
	spin_lock(&task->files->file_lock);
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
		struct files_struct *f = task->files;
#else
		struct fdtable *f = task->files->fdt;
#endif
		for (fd = 0; fd < f->max_fds; fd++)
			if (f->fd[fd])
				(*callback)(f->fd[fd], user_data);
	}
	spin_unlock(&task->files->file_lock);
	task_unlock(task);
}


// Destroy a osprd_info_t.

static void cleanup_device(osprd_info_t *d)
{
	wake_up_all(&d->blockq);
	if (d->gd) {
		del_gendisk(d->gd);
		put_disk(d->gd);
	}
	if (d->queue)
		blk_cleanup_queue(d->queue);
	if (d->data)
		vfree(d->data);
}


// Initialize a osprd_info_t.

static int setup_device(osprd_info_t *d, int which)
{
	memset(d, 0, sizeof(osprd_info_t));

	/* Get memory to store the actual block data. */
	if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
		return -1;
	memset(d->data, 0, nsectors * SECTOR_SIZE);

	/* Set up the I/O queue. */
	spin_lock_init(&d->qlock);
	if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
		return -1;
	blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
	d->queue->queuedata = d;

	/* The gendisk structure. */
	if (!(d->gd = alloc_disk(1)))
		return -1;
	d->gd->major = OSPRD_MAJOR;
	d->gd->first_minor = which;
	d->gd->fops = &osprd_ops;
	d->gd->queue = d->queue;
	d->gd->private_data = d;
	snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
	set_capacity(d->gd, nsectors);
	add_disk(d->gd);

	/* Call the setup function. */
	osprd_setup(d);

	return 0;
}

static void osprd_exit(void);


// The kernel calls this function when the module is loaded.
// It initializes the 4 osprd block devices.

static int __init osprd_init(void)
{
	int i, r;

	// shut up the compiler
	(void) for_each_open_file;
#ifndef osp_spin_lock
	(void) osp_spin_lock;
	(void) osp_spin_unlock;
#endif

	/* Register the block device name. */
	if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
		printk(KERN_WARNING "osprd: unable to get major number\n");
		return -EBUSY;
	}

	/* Initialize the device structures. */
	for (i = r = 0; i < NOSPRD; i++)
		if (setup_device(&osprds[i], i) < 0)
			r = -EINVAL;

	if (r < 0) {
		printk(KERN_EMERG "osprd: can't set up device structures\n");
		osprd_exit();
		return -EBUSY;
	} else
		return 0;
}


// The kernel calls this function to unload the osprd module.
// It destroys the osprd devices.

static void osprd_exit(void)
{
	int i;
	for (i = 0; i < NOSPRD; i++)
		cleanup_device(&osprds[i]);
	unregister_blkdev(OSPRD_MAJOR, "osprd");
}


// Tell Linux to call those functions at init and exit time.
module_init(osprd_init);
module_exit(osprd_exit);
