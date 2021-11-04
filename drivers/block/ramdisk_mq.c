// SPDX-FileCopyrightText: Copyright (c) 2019 Kookmin University
// Multi Queue features implemeneted
// SPDX-License-Identifier: GPL-2.0-only

/*
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 * 
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/blk-mq.h>
#include <linux/nodemask.h>

#define RWA_MASK REQ_RAHEAD
#define READA RWA_MASK

#ifdef pr_warn
#undef pr_warn
#endif
#define pr_warn(fmt, arg...) printk(KERN_WARNING "ramdisk_mq: "fmt, ##arg)

#define SECTOR_SHIFT        9
#define PAGE_SECTORS_SHIFT  (PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS        (1 << PAGE_SECTORS_SHIFT)

//#define RAMDISK_MQ_BLOCK_MAJOR    249

MODULE_LICENSE("GPL");

struct ramdisk_mq_cmd{
    struct list_head list;
    struct llist_node ll_list;
    //struct call_single_data csd;
    struct request *rq;
    struct bio *bio;
    unsigned int tag;
    struct nullb_queue *nq;
    struct hrtimer timer;
};

struct nullb_queue{
    unsigned long *tag_map;
    wait_queue_head_t wait;
    unsigned int queue_depth;

    struct ramdisk_mq_cmd *cmds;
};

enum {
    RAMDISK_MQ_Q_BIO        = 0, // process IO in bio by bio
    RAMDISK_MQ_Q_RQ     = 1, // IO in request base
    RAMDISK_MQ_Q_MQ     = 2,
};

enum {
    RAMDISK_MQ_IRQ_NONE     = 0,
    RAMDISK_MQ_IRQ_SOFTIRQ  = 1,
};

struct ramdisk_mq_hw_queue_private {
    unsigned int index;
    unsigned int queue_depth;
    struct ramdisk_mq_device *ramdisk_mq;
};

struct ramdisk_mq_device {
    struct request_queue *ramdisk_mq_queue;
    struct gendisk *ramdisk_mq_disk;
    spinlock_t ramdisk_mq_lock;
    spinlock_t ramdisk_mq_queue_lock;
    struct radix_tree_root ramdisk_mq_pages;

    // for mq
    struct ramdisk_mq_hw_queue_private *hw_queue_priv;
    struct blk_mq_tag_set tag_set;
    unsigned int queue_depth;
};


static int ramdisk_mq_major;
struct ramdisk_mq_device *global_ramdisk_mq;
// sw submit queues for per-cpu or per-node
static int nr_hw_queues = 1;
module_param(nr_hw_queues, int, S_IRUGO);
MODULE_PARM_DESC(nr_hw_queues, "nr_submit_queue");

static int hw_queue_depth = 128;
module_param(hw_queue_depth, int, S_IRUGO);
MODULE_PARM_DESC(hw_queue_depth, "hw_queue_depth");

static int queue_mode = RAMDISK_MQ_Q_MQ;
module_param(queue_mode, int, S_IRUGO);
MODULE_PARM_DESC(queue_mode, "queue_mode 0-bio, 1-rq, 2-mq");

static int ramdisk_mq_size = 4*1024*1024;
module_param(ramdisk_mq_size, int, S_IRUGO);
MODULE_PARM_DESC(ramdisk_mq_size, "ramdisk_mq size, default = 4M");

static struct page *ramdisk_mq_lookup_page(struct ramdisk_mq_device *ramdisk_mq,
        sector_t sector)
{
    pgoff_t idx;
    struct page *p;

    rcu_read_lock(); // why rcu-read-lock?

    // 9 = SECTOR_SHIFT
    idx = sector >> (PAGE_SHIFT - 9);
    p = radix_tree_lookup(&ramdisk_mq->ramdisk_mq_pages, idx);

    rcu_read_unlock();

    //pr_warn("lookup: page-%p index-%d sector-%d\n",
    //  p, p ? (int)p->index : -1, (int)sector);
    return p;
}

static struct page *ramdisk_mq_insert_page(struct ramdisk_mq_device *ramdisk_mq,
        sector_t sector)
{
    pgoff_t idx;
    struct page *p;
    gfp_t gfp_flags;

    p = ramdisk_mq_lookup_page(ramdisk_mq, sector);
    if (p)
        return p;

    // must use _NOIO
    gfp_flags = GFP_NOIO | __GFP_ZERO;
    p = alloc_page(gfp_flags);
    if (!p)
        return NULL;

    if (radix_tree_preload(GFP_NOIO)) {
        __free_page(p);
        return NULL;
    }

    // According to radix tree API document,
    // radix_tree_lookup() requires rcu_read_lock(),
    // but user must ensure the sync of calls to radix_tree_insert().
    spin_lock(&ramdisk_mq->ramdisk_mq_lock);

    // #sector -> #page
    // one page can store 8-sectors
    idx = sector >> (PAGE_SHIFT - 9);
    p->index = idx;

    if (radix_tree_insert(&ramdisk_mq->ramdisk_mq_pages, idx, p)) {
        __free_page(p);
        p = radix_tree_lookup(&ramdisk_mq->ramdisk_mq_pages, idx);
        //pr_warn("failed to insert page: duplicated=%d\n",
        //  (int)idx);
    } else {
        //pr_warn("insert: page-%p index=%d sector-%d\n",
        //  p, (int)idx, (int)sector);
    }

    spin_unlock(&ramdisk_mq->ramdisk_mq_lock);

    radix_tree_preload_end();

    return p;
}
/*
   static void show_data(unsigned char *ptr)
   {
   pr_warn("%x %x %x %x %x %x %x %x\n",
   ptr[0], ptr[1], ptr[2], ptr[3],
   ptr[4], ptr[5], ptr[6], ptr[7]);
   }
 */
static int copy_from_user_to_ramdisk_mq(struct ramdisk_mq_device *ramdisk_mq,
        struct page *src_page,
        int len,
        unsigned int src_offset,
        sector_t sector)
{
    struct page *dst_page;
    void *dst;
    unsigned int target_offset;
    size_t copy;
    void *src;
    // sectors can be stored across two pages
    // 8 = one page can have 8-sectors
    // target_offset = sector * 512(sector-size) = target_offset in a page
    // eg) sector = 123, size=4096
    // page1 <- sector120 ~ sector127
    // page2 <- sector128 ~ sector136
    // store 512*5-bytes at page1 (sector 123~127)
    // store 512*3-bytes at page2 (sector 128~130)
    // page1->index = 120, page2->index = 128
    //pr_warn("start user_to_ramdisk_mq\n");
    target_offset = (sector & (8 - 1)) << 9;
    // copy = copy data in a page
    copy = min_t(size_t, len, PAGE_SIZE - target_offset);

    dst_page = ramdisk_mq_lookup_page(ramdisk_mq, sector);
    if (!dst_page) {
        // First added data, need to make space to store data

        // insert the first page
        if (!ramdisk_mq_insert_page(ramdisk_mq, sector))
            return -ENOSPC;

        if (copy < len) {
            if (!ramdisk_mq_insert_page(ramdisk_mq, sector + (copy >> 9)))
                return -ENOSPC;
        }

        // now it cannot fail
        dst_page = ramdisk_mq_lookup_page(ramdisk_mq, sector);
        BUG_ON(!dst_page);
    }

    src = kmap(src_page);
    src += src_offset;

    dst = kmap(dst_page);
    memcpy(dst + target_offset, src, copy);
    kunmap(dst_page);

    //pr_warn("copy: %p <- %p (%d-bytes)\n", dst + target_offset, src, (int)copy);
    //show_data(dst+target_offset);
    //show_data(src);

    // copy next page
    if (copy < len) {
        src += copy;
        sector += (copy >> 9);
        copy = len - copy;
        dst_page = ramdisk_mq_lookup_page(ramdisk_mq, sector);
        BUG_ON(!dst_page);

        dst = kmap(dst_page); // next page

        // dst: copy data at the first address of the page
        memcpy(dst, src, copy);
        kunmap(dst_page);

        //pr_warn("copy: %p <- %p (%d-bytes)\n", dst + target_offset, src, (int)copy);
        //show_data(dst);
        //show_data(src);
    }
    kunmap(src_page);

    //pr_warn("end user_to_ramdisk_mq\n");
    return 0;
}

static int copy_from_ramdisk_mq_to_user(struct ramdisk_mq_device *ramdisk_mq,
        struct page *dst_page,
        int len,
        unsigned int dst_offset,
        sector_t sector)
{
    struct page *src_page;
    void *src;
    size_t copy;
    void *dst;
    unsigned int src_offset;

    //pr_warn("start ramdisk_mq_to_user\n");
    src_offset = (sector & 0x7) << 9;
    copy = min_t(size_t, len, PAGE_SIZE - src_offset);

    dst = kmap(dst_page);
    dst += dst_offset;

    src_page = ramdisk_mq_lookup_page(ramdisk_mq, sector);
    if (src_page) {
        src = kmap_atomic(src_page);
        src += src_offset;
        memcpy(dst, src, copy);
        kunmap_atomic(src);
        //pr_warn("copy: %p <- %p (%d-bytes)\n", dst, src, (int)copy);
        //show_data(dst);
        //show_data(src);
    } else {
        memset(dst, 0, copy);
        //pr_warn("copy: %p <- 0 (%d-bytes)\n", dst, (int)copy);
        //pr_warn("3\n");
        //show_data(dst);
        //pr_warn("4\n");
    }

    if (copy < len) {
        dst += copy;
        sector += (copy >> 9); // next sector
        copy = len - copy; // remain data
        src_page = ramdisk_mq_lookup_page(ramdisk_mq, sector);
        if (src_page) {
            src = kmap_atomic(src_page);
            memcpy(dst, src, copy);
            kunmap_atomic(src);

            //pr_warn("copy: %p <- %p (%d-bytes)\n", dst, src, (int)copy);
            //show_data(dst);
            //show_data(src);
        } else {
            memset(dst, 0, copy);
            //pr_warn("copy: %p <- 0 (%d-bytes)\n", dst, (int)copy);
            //show_data(dst);
        }
    }

    kunmap(dst_page);
    //pr_warn("end ramdisk_mq_to_user\n");
    return 0;
}

static void ramdisk_mq_free_page(struct ramdisk_mq_device *ramdisk_mq, sector_t sector)
{
    struct page *page;
    pgoff_t idx;

    spin_lock(&ramdisk_mq->ramdisk_mq_lock);
    idx = sector >> PAGE_SECTORS_SHIFT;
    page = radix_tree_delete(&ramdisk_mq->ramdisk_mq_pages, idx);
    spin_unlock(&ramdisk_mq->ramdisk_mq_lock);
    if (page)
        __free_page(page);
}

static void ramdisk_mq_zero_page(struct ramdisk_mq_device *ramdisk_mq, sector_t sector)
{
    struct page *page;

    page = ramdisk_mq_lookup_page(ramdisk_mq, sector);
    if (page)
        clear_highpage(page);
}

#define FREE_BATCH 16
static void ramdisk_mq_free_pages(struct ramdisk_mq_device *ramdisk_mq)
{
    unsigned long pos = 0;
    struct page *pages[FREE_BATCH];
    int nr_pages;

    do {
        int i;

        nr_pages = radix_tree_gang_lookup(&ramdisk_mq->ramdisk_mq_pages,
                (void **)pages, pos, FREE_BATCH);

        for (i = 0; i < nr_pages; i++) {
            void *ret;

            BUG_ON(pages[i]->index < pos);
            pos = pages[i]->index;
            ret = radix_tree_delete(&ramdisk_mq->ramdisk_mq_pages, pos);
            BUG_ON(!ret || ret != pages[i]);
            __free_page(pages[i]);
        }

        pos++;

        /*
         * This assumes radix_tree_gang_lookup always returns as
         * many pages as possible. If the radix-tree code changes,
         * so will this have to.
         */
    } while (nr_pages == FREE_BATCH);
}



static void discard_from_ramdisk_mq(struct ramdisk_mq_device *ramdisk_mq,
        sector_t sector, size_t n)
{
    while (n >= PAGE_SIZE) {
        /*
         * Don't want to actually discard pages here because
         * re-allocating the pages can result in writeback
         * deadlocks under heavy load.
         */
        if (0)
            ramdisk_mq_free_page(ramdisk_mq, sector);
        else
            ramdisk_mq_zero_page(ramdisk_mq, sector);
        sector += PAGE_SIZE >> SECTOR_SHIFT;
        n -= PAGE_SIZE;
    }
}


static blk_qc_t ramdisk_mq_make_request_fn(struct request_queue *q, struct bio *bio)
{
    //struct block_device *bdev = bio->bi_bdev;
    struct ramdisk_mq_device *ramdisk_mq = bio->bi_disk->private_data;
    int rw;
    struct bio_vec bvec;
    sector_t sector;
    sector_t end_sector;
    struct bvec_iter iter;

    //pr_warn("start ramdisk_mq_make_request_fn: block_device=%p ramdisk_mq=%p\n",
    //  bdev, ramdisk_mq);

    //dump_stack();

    // print info of bio
    sector = bio->bi_iter.bi_sector;
    end_sector = bio_end_sector(bio);
    if (end_sector > get_capacity(bio->bi_disk))
        goto io_error;
    rw = bio_op(bio);
    //pr_warn("bio-info: sector=%d end_sector=%d rw=%s\n",
    //  (int)sector, (int)end_sector, rw == READ ? "READ" : "WRITE");

    //if (unlikely(bio->bi_opf & REQ_DISCARD)) {
    if (unlikely(bio_op(bio) == 3)) {
        if (sector & ((PAGE_SIZE >> SECTOR_SHIFT) - 1) ||
                bio->bi_iter.bi_size & PAGE_MASK)
            goto io_error;
        discard_from_ramdisk_mq(ramdisk_mq, sector, bio->bi_iter.bi_size);
        goto out;
    }

    // ffffffff81187890 t end_bio_bh_io_sync
    //pr_warn("bio-info: end-io=%p\n", bio->bi_end_io);


    bio_for_each_segment(bvec, bio, iter) {
        unsigned int len = bvec.bv_len;
        struct page *p = bvec.bv_page;
        unsigned int offset = bvec.bv_offset;
        int err;

        //pr_warn("bio-info: len=%u p=%p offset=%u\n",
        //  len, p, offset);

        // The reason of flush-dcache
        // https://patchwork.kernel.org/patch/2742
        // You have to call fluch_dcache_page() in two situations,
        // when the kernel is going to read some data that userspace wrote, *and*
        // when userspace is going to read some data that the kernel wrote.

        if (rw == READ || rw == READA) {
            // kernel write data from kernelspace into userspace
            err = copy_from_ramdisk_mq_to_user(ramdisk_mq,
                    p,
                    len,
                    offset,
                    sector);
            if (err)
                goto io_error;

            // userspace is going to read data that the kernel just wrote
            // so flush-dcache is necessary
            flush_dcache_page(page);
        } else if (rw == WRITE) {
            // kernel is going to read data that userspace wrote,
            // so flush-dcache is necessary
            flush_dcache_page(page);
            err = copy_from_user_to_ramdisk_mq(ramdisk_mq,
                    p,
                    len,
                    offset,
                    sector);
            if (err)
                goto io_error;
        } else {
            //pr_warn("rw is not READ/WRITE\n");
            goto io_error;
        }

        if (err)
            goto io_error;

        sector = sector + (len >> 9);
    }

    // when disk is added, make_request is called..why??

out:    
    bio_endio(bio);

    //pr_warn("end ramdisk_mq_make_request_fn\n");
    // no cookie
    return BLK_QC_T_NONE;
io_error:
    bio_io_error(bio);
    return BLK_QC_T_NONE;
}


static int ramdisk_mq_ioctl(struct block_device *bdev, fmode_t mode,
        unsigned int cmd, unsigned long arg)
{
    int error = 0;
    //pr_warn("start ramdisk_mq_ioctl\n");

    //pr_warn("end ramdisk_mq_ioctl\n");
    return error;
}

static const struct block_device_operations ramdisk_mq_fops = {
    .owner =        THIS_MODULE,
    .ioctl =        ramdisk_mq_ioctl,
};

/*
 * request_fn, prep_rq_fn, softirq_done_fn are for RequestQueue-base mode
 */
static int irqmode = RAMDISK_MQ_IRQ_NONE/* RAMDISK_MQ_IRQ_SOFTIRQ */;
/*
   static int ramdisk_mq_prep_rq_fn(struct request_queue *q, struct request *req)
   {
   struct ramdisk_mq_device *ramdisk_mq = q->queuedata;

//pr_warn("start prep_rq_fn: q=%p req=%p\n", q, req);
//dump_stack();

if (req->special) {
return BLKPREP_KILL;
}

req->special = ramdisk_mq;

//pr_warn("prep-request: len=%d disk=%p start_time=%lu end_io=%p\n",
//  (int)req->__data_len, req->rq_disk,
//  req->start_time, req->end_io);
//pr_warn("end prep_rq_fn\n");
return BLKPREP_OK;
}
 */

static int _ramdisk_mq_request_fn(struct request *req)
{
    struct bio_vec bvec;
    struct req_iterator iter;
    unsigned int len;
    struct page *p;
    unsigned int offset;
    sector_t sector;
    struct ramdisk_mq_device *ramdisk_mq = req->q->queuedata;
    int err;
    if (req->special != req->q->queuedata) {
        //pr_warn("\nunknown request error\n\n");
        goto io_error;
    }

    sector = blk_rq_pos(req); // initial sector
    //pr_warn("start_rq_for_each_segment\n");
    //pr_warn("req->bio:%s\n", ((req->bio))?"true":"false"); 
    //pr_warn("sector = %d \n", (int)sector);
    if ((req->bio))
        for (iter.bio = (req)->bio; iter.bio; iter.bio = iter.bio->bi_next){
            //pr_warn("iter.bio->bi_iter.bi_idx = %d , iter.bio->bi_iter.bi_sector = %llu \n",iter.bio->bi_iter.bi_idx, (unsigned long long)iter.bio->bi_iter.bi_sector);
            //iter.iter = ((iter.bio)->bi_iter); 
            //pr_warn("(iter.iter).bi_size = %d \n", (iter.iter).bi_size); 

            //pr_warn("iter.bio.bi_vcnt = %d , iter.bio.bi_max_vecs = %d \n", iter.bio->bi_vcnt , iter.bio->bi_max_vecs);

            //pr_warn("iter.bio->bi_io_vec.len = %d , iter.bio->bi_io_vec.offset = %d \n", iter.bio->bi_io_vec->bv_len, iter.bio->bi_io_vec->bv_offset);

            //pr_warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            //pr_warn("t_or_f = %d\n",(bvec = bio_iter_iovec((iter.bio),(iter.iter)),1));
            //pr_warn("bvec\n"); 
            //if(bvec.bv_page == NULL) 
            //{pr_warn("page\n");}
            //if(bvec.bv_len == NULL) 
            //{pr_warn("len\n");}
            //if(bvec.bv_offset == NULL) 
            //{pr_warn("offset\n");}
            if(iter.bio->bi_vcnt == 0)
                continue;


            for(iter.iter = ((iter.bio)->bi_iter); (iter.iter).bi_size && ((bvec = bio_iter_iovec((iter.bio),(iter.iter))),1); bio_advance_iter((iter.bio), &(iter.iter), (bvec).bv_len)) {

                //pr_warn("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
                //rq_for_each_segment(bvec, req, iter) {
                //pr_warn("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
                len = bvec.bv_len;
                p = bvec.bv_page;
                //pr_warn("###################################\n");

                if(p == NULL)
                {
                    break;}
                offset = bvec.bv_offset;
                //pr_warn("sector=%d bio-info: len=%u p=%p offset=%u\n",
                //  (int)sector, len, p, offset);

                if (rq_data_dir(req)) { // WRITE 
                    flush_dcache_page(page);
                    err = copy_from_user_to_ramdisk_mq(ramdisk_mq,
                            p,
                            len,
                            offset,
                            sector);
                    if (err) {
                        //       pr_warn("    request_fn: failed to"
                        //         "write sector\n");
                        goto io_error;
                    }
                } else { // READ
                    err = copy_from_ramdisk_mq_to_user(ramdisk_mq,
                            p,
                            len,
                            offset,
                            sector);
                    if (err) {
                        //     pr_warn("    request_fn: failed to"
                        //       "read sector\n");
                        goto io_error;
                    }
                    flush_dcache_page(page);
                    //pr_warn("4\n");
                }
                sector += (len >> 9);
            }
            //if(iter.bio->bi_next == NULL) 
            //{pr_warn("iter.bio->bi_next");break;}


            }
            //pr_warn("end_rq_for_each_segment\n");
            return 0;
io_error:
            return -EIO;
        }
    /*
       void blk_end_request_all(struct request *rq, int error)
       {
       bool pending;
       unsigned int bidi_bytes = 0;

       if (unlikely(blk_bidi_rq(rq)))
       bidi_bytes = blk_rq_bytes(rq->next_rq);

       pending = blk_end_bidi_request(rq, error, blk_rq_bytes(rq), bidi_bytes);
       BUG_ON(pending);
       }
     */

    /*
       static void ramdisk_mq_softirq_done_fn(struct request *req)
       {
    //pr_warn("start softirq_done_fn: complete delayed request: %p", req);
    list_del_init(&req->queuelist);
    blk_end_request_all(req, 0);
    //pr_warn("end softirq_done_fn\n");
    }
     */

    /*
       static void ramdisk_mq_request_fn(struct request_queue *q)
       {
       struct request *req;
       int err = 0;
    //pr_warn("start request_fn: q=%p irqmode=%d\n", q, irqmode);
    //dump_stack();

    // blk_fetch_request() extracts the request from the queue
    // so the req->queuelist should be empty
    while ((req = blk_fetch_request(q)) != NULL) {
    spin_unlock_irq(q->queue_lock);

//pr_warn("  fetch-request: req=%p len=%d rw=%s\n",
//  req, (int)blk_rq_bytes(req),
//  rq_data_dir(req) ? "WRITE":"READ");

switch (irqmode) {
case RAMDISK_MQ_IRQ_NONE:
    //pr_warn("start ramdisk_mq_request_fn\n");
    err = _ramdisk_mq_request_fn(req);
    blk_end_request_all(req, err); // finish the request
    //pr_warn("end ramdisk_mq_request_fn\n");
    break;
    case RAMDISK_MQ_IRQ_SOFTIRQ:
    // pass request into per-cpu list blk_cpu_done
    // softirq_done_fn will be called for each request
    blk_complete_request(req);
    break;
    }

    spin_lock_irq(q->queue_lock); // lock q before fetching request
    }
    //pr_warn("end request_fn\n");
    }
     */
    /*
    //5.0ver
    static blk_status_t ramdisk_mq_queue_rq(struct blk_mq_hw_ctx *hctx,
    const struct blk_mq_queue_data *bd) 
    {
    struct nullb_cmd *cmd = blk_mq_rq_to_pdu(bd->rq);
    struct nullb_queue *nq = hctx->driver_data;

    might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);

    if (nq->dev->irqmode == NULL_IRQ_TIMER) {
    hrtimer_init(&cmd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    cmd->timer.function = null_cmd_timer_expired;
    }    
    cmd->rq = bd->rq;
    cmd->nq = nq;

    blk_mq_start_request(bd->rq);

    if (should_requeue_request(bd->rq)) {
    nq->requeue_selection++;
    if (nq->requeue_selection & 1) 
    return BLK_STS_RESOURCE;
    else {
    blk_mq_requeue_request(bd->rq, true);
    return BLK_STS_OK;
    }
    }    
    if (should_timeout_request(bd->rq))
    return BLK_STS_OK;

    return null_handle_cmd(cmd);
    }
     */
    /*
       static void put_tag(struct nullb_queue *nq, unsigned int tag)
       {
       clear_bit_unlock(tag, nq->tag_map);

       if (waitqueue_active(&nq->wait))
       wake_up(&nq->wait);
       }

       static void free_cmd(struct ramdisk_mq_cmd *cmd)
       {
       put_tag(cmd->nq, cmd->tag);
       }

       static void end_cmd(struct ramdisk_mq_cmd *cmd)
       {
       struct request_queue *q = NULL;

       if (cmd->rq)
       q = cmd->rq->q;

       switch (queue_mode)  {
       case RAMDISK_MQ_Q_MQ:
       blk_mq_end_request(cmd->rq, 0);
       return;
       case RAMDISK_MQ_Q_BIO:
       bio_endio(cmd->bio);
       break;
       }

       free_cmd(cmd);
       } 

       static inline void null_handle_cmd(struct ramdisk_mq_cmd *cmd)
       {
       if(likely(irqmode == RAMDISK_MQ_IRQ_NONE))
       end_cmd(cmd);
       } 
    //4.4ver
    static int ramdisk_mq_queue_rq(struct blk_mq_hw_ctx *hctx,
    const struct blk_mq_queue_data *bd)
    {
    struct ramdisk_mq_cmd *cmd = blk_mq_rq_to_pdu(bd->rq);

    cmd->rq = bd->rq;
    cmd->nq = hctx->driver_data;

    blk_mq_start_request(bd->rq);
    null_handle_cmd(cmd);
    //return BLK_MQ_RQ_QUEUE_OK;
    return 0;
    }
     */

    //original
    // hw-queue: submit IOs into hw
    static blk_status_t ramdisk_mq_queue_rq(struct blk_mq_hw_ctx *hctx,
            const struct blk_mq_queue_data *bd)
    {
        struct request *req = bd->rq;
        struct ramdisk_mq_hw_queue_private *priv = hctx->driver_data;
        struct ramdisk_mq_device *pdu_ramdisk_mq = blk_mq_rq_to_pdu(bd->rq);

        BUG_ON(irqmode != RAMDISK_MQ_IRQ_NONE);

        *pdu_ramdisk_mq = *(priv->ramdisk_mq); // example to use pdu area
        //dump_stack();

        blk_mq_start_request(req);

        req->special = priv->ramdisk_mq;

        _ramdisk_mq_request_fn(req);

        blk_mq_end_request(req, 0);
        //pr_warn("end queue_rq\n");
        //return BLK_MQ_RQ_QUEUE_OK;
        return BLK_STS_OK;
    }

    static int ramdisk_mq_init_hctx(struct blk_mq_hw_ctx *hctx,
            void *data,
            unsigned int index)
    {
        struct ramdisk_mq_device *ramdisk_mq = data;
        struct ramdisk_mq_hw_queue_private *priv = &ramdisk_mq->hw_queue_priv[index];

        BUG_ON(!ramdisk_mq);
        BUG_ON(!priv);

        //pr_warn("start init_hctx: hctx=%p ramdisk_mq=%p priv[%d]=%p\n",
        //  hctx, ramdisk_mq, index, priv);
        //pr_warn("info hctx: numa_node=%d queue_num=%d queue->%p\n",
        //  (int)hctx->numa_node, (int)hctx->queue_num, hctx->queue);
        //dump_stack();

        priv->index = index;
        priv->queue_depth = ramdisk_mq->queue_depth;
        priv->ramdisk_mq = ramdisk_mq;
        hctx->driver_data = priv;

        //pr_warn("end init_hctx\n");
        return 0;
    }

    static struct blk_mq_ops ramdisk_mq_mq_ops = {
        .queue_rq = ramdisk_mq_queue_rq,
        //.map_queue = blk_mq_map_queue,
        .init_hctx = ramdisk_mq_init_hctx,
        //.complete = ramdisk_mq_softirq_done_fn, // share mq-mode and request-mode
    };

    static struct ramdisk_mq_device *ramdisk_mq_alloc(void)
    {
        struct ramdisk_mq_device *ramdisk_mq;
        struct gendisk *disk;
        int ret;

        //pr_warn("start ramdisk_mq_alloc\n");
        ramdisk_mq = kzalloc(sizeof(*ramdisk_mq), GFP_KERNEL);
        if (!ramdisk_mq)
            goto out;

        spin_lock_init(&ramdisk_mq->ramdisk_mq_lock);
        spin_lock_init(&ramdisk_mq->ramdisk_mq_queue_lock);
        INIT_RADIX_TREE(&ramdisk_mq->ramdisk_mq_pages, GFP_ATOMIC);

        //pr_warn("create queue: ramdisk_mq-%p queue-mode-%d\n", ramdisk_mq, queue_mode);

        if (queue_mode == RAMDISK_MQ_Q_BIO) {
            ramdisk_mq->ramdisk_mq_queue = blk_alloc_queue_node(GFP_KERNEL,
                    NUMA_NO_NODE);
            if (!ramdisk_mq->ramdisk_mq_queue)
                goto out_free_ramdisk_mq;
            blk_queue_make_request(ramdisk_mq->ramdisk_mq_queue,
                    ramdisk_mq_make_request_fn);
        } /*
             else if (queue_mode == RAMDISK_MQ_Q_RQ) {
             ramdisk_mq->ramdisk_mq_queue = blk_init_queue_node(ramdisk_mq_request_fn,
             &ramdisk_mq->ramdisk_mq_queue_lock,
             NUMA_NO_NODE);
             if (!ramdisk_mq->ramdisk_mq_queue) {
        //pr_warn("failed to create RQ-queue\n");
        goto out_free_ramdisk_mq;
        }
        blk_queue_prep_rq(ramdisk_mq->ramdisk_mq_queue, ramdisk_mq_prep_rq_fn);
        blk_queue_softirq_done(ramdisk_mq->ramdisk_mq_queue,
        ramdisk_mq_softirq_done_fn);
        } */
             else if (queue_mode == RAMDISK_MQ_Q_MQ) {
                 ramdisk_mq->hw_queue_priv = kzalloc(nr_hw_queues *
                         sizeof(struct ramdisk_mq_hw_queue_private),
                         GFP_KERNEL);
                 if (!ramdisk_mq->hw_queue_priv) {
                     //pr_warn("failed to create queues for mq-mode\n");
                     goto out_free_ramdisk_mq;
                 }

                 ramdisk_mq->queue_depth = hw_queue_depth;
                 ramdisk_mq->tag_set.ops = &ramdisk_mq_mq_ops;
                 ramdisk_mq->tag_set.nr_hw_queues = nr_hw_queues;
                 ramdisk_mq->tag_set.queue_depth = hw_queue_depth;
                 ramdisk_mq->tag_set.numa_node = NUMA_NO_NODE;
                 ramdisk_mq->tag_set.cmd_size = sizeof(struct ramdisk_mq_device);
                 ramdisk_mq->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
                 ramdisk_mq->tag_set.driver_data = ramdisk_mq;

                 ret = blk_mq_alloc_tag_set(&ramdisk_mq->tag_set);
                 if (ret) {
                     //pr_warn("failed to allocate tag-set\n");
                     goto out_free_queue;
                 }

                 ramdisk_mq->ramdisk_mq_queue = blk_mq_init_queue(&ramdisk_mq->tag_set);
                 if (IS_ERR(ramdisk_mq->ramdisk_mq_queue)) {
                     //pr_warn("failed to init queue for mq-mode\n");
                     goto out_free_tag;
                 }
             }

             ramdisk_mq->ramdisk_mq_queue->queuedata = ramdisk_mq;
             blk_queue_max_hw_sectors(ramdisk_mq->ramdisk_mq_queue, 1024);
             blk_queue_bounce_limit(ramdisk_mq->ramdisk_mq_queue, BLK_BOUNCE_ANY);
             blk_queue_physical_block_size(ramdisk_mq->ramdisk_mq_queue, PAGE_SIZE);
             blk_queue_logical_block_size(ramdisk_mq->ramdisk_mq_queue, PAGE_SIZE);
             ramdisk_mq->ramdisk_mq_queue->limits.discard_granularity = PAGE_SIZE;
             blk_queue_max_discard_sectors(ramdisk_mq->ramdisk_mq_queue, UINT_MAX);
             //ramdisk_mq->ramdisk_mq_queue->limits.discard_zeroes_data = 1;
             //queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, ramdisk_mq->ramdisk_mq_queue);
             blk_queue_flag_set(QUEUE_FLAG_DISCARD, ramdisk_mq->ramdisk_mq_queue);

             disk = ramdisk_mq->ramdisk_mq_disk = alloc_disk(1);
             if (!disk)
                 goto out_free_queue;

             disk->major = ramdisk_mq_major;
             disk->first_minor = 111;
             disk->fops = &ramdisk_mq_fops;
             disk->private_data = ramdisk_mq;
             disk->queue = ramdisk_mq->ramdisk_mq_queue;
             disk->flags = GENHD_FL_EXT_DEVT;
             strncpy(disk->disk_name, "ramdisk_mq", strlen("ramdisk_mq"));
             set_capacity(disk, ramdisk_mq_size >> 9);

             add_disk(disk);
             //pr_warn("end ramdisk_mq_alloc\n");

             return ramdisk_mq;
out_free_tag:
             if (queue_mode == RAMDISK_MQ_Q_MQ)
                 blk_mq_free_tag_set(&ramdisk_mq->tag_set);
out_free_queue:
             if (queue_mode == RAMDISK_MQ_Q_MQ) {
                 kfree(ramdisk_mq->hw_queue_priv);
             } else {
                 blk_cleanup_queue(ramdisk_mq->ramdisk_mq_queue);
             }
out_free_ramdisk_mq:
             kfree(ramdisk_mq);
out:
             return NULL;
    }

    static void ramdisk_mq_free(struct ramdisk_mq_device *ramdisk_mq)
    {
        put_disk(global_ramdisk_mq->ramdisk_mq_disk);
        blk_cleanup_queue(global_ramdisk_mq->ramdisk_mq_queue);
        ramdisk_mq_free_pages(ramdisk_mq);
        kfree(global_ramdisk_mq);
    }

    static int __init ramdisk_mq_init(void)
    {
        pr_warn("\n\n\nramdisk_mq: module loaded\n\n\n\n");
        ramdisk_mq_major = register_blkdev(ramdisk_mq_major, "my-ramdisk");
        //ramdisk_mq_major = register_blkdev(RAMDISK_MQ_BLOCK_MAJOR, "my-ramdisk");
        if (ramdisk_mq_major < 0)
            return ramdisk_mq_major;

        //pr_warn("ramdisk_mq major=%d\n", ramdisk_mq_major);
        global_ramdisk_mq = ramdisk_mq_alloc();
        if (!global_ramdisk_mq) {
            //pr_warn("failed to initialize ramdisk_mq\n");
            unregister_blkdev(ramdisk_mq_major, "my-ramdisk");
            //unregister_blkdev(RAMDISK_MQ_BLOCK_MAJOR, "my-ramdisk");
            return -1;
        }
        //pr_warn("global-ramdisk_mq=%p\n", global_ramdisk_mq);
        return 0;
    }

    static void __exit ramdisk_mq_exit(void)
    {
        del_gendisk(global_ramdisk_mq->ramdisk_mq_disk);
        ramdisk_mq_free(global_ramdisk_mq);
        unregister_blkdev(ramdisk_mq_major, "my-ramdisk");
        //unregister_blkdev(RAMDISK_MQ_BLOCK_MAJOR, "my-ramdisk");
        pr_warn("ramdisk_mq: module unloaded\n");
    }

    module_init(ramdisk_mq_init);
    module_exit(ramdisk_mq_exit);

