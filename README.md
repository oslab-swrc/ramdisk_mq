# ramdisk_mq

The goal of this project is to evaluate the scalability of the Multi-Queue *Block* IO Queueing Mechanism (blk-mq) of Linux OS. Ramdisk_MQ is a RAM-based block device that enables evaluating the manycore scalability of blk-mq with very high I/O intensity. Ramdisk_mq's performance is far exceeding the IOPS value achievable from the state of the art NVMe SSDs. 

## Information

The concept of emulating a block device using RAM is not new. However, no existing solution can be directly attached to blk-mq, which motivated us to devise Ramdisk_MQ. Ramdisk_MQ enables that all I/O requests are actually passing through blk-mq before arriving to RAM.

#### Requirement List

- Source code update to run with newer version of kernel(5.1 or later)


## Licence

GPL-2.0


## Usage

If you want to use ramdisk_mq, you need to build kernel first.

#### Build
##### Setup

```bash
make menuconfig
```
You may get this screen.

![menuconfig](https://user-images.githubusercontent.com/13490996/139576611-f2c33681-f71d-4822-a3f7-284d950d41c9.png)

-> Device Drivers

![device_drivers](https://user-images.githubusercontent.com/13490996/139576615-f74e5755-358f-461c-80b5-a6f405a410d4.png)

-> Block devices

![block_deivces](https://user-images.githubusercontent.com/13490996/139576625-5c1c4a21-5e85-421a-85cd-bf200f8ef376.png)

Set 'm' to RAMDISK_MQ block device support
![ramdisk_mq](https://user-images.githubusercontent.com/13490996/139576646-7dd3d433-6bb1-487f-b025-2e05ec7e0876.png)

SAVE & EXIT

OR

Search BLK_DEV_RAMDISK_MQ in config and set to 'm'.

##### Build Command

```bash
make -j$((`nproc`+1)) && make modules -j$((`nproc`+1)) && make modules_install -j$((`nproc`+1)) INSTALL_MOD_STRIP=1 && make install -j$((`nproc`+1))
```

This command detect core count and build with -j{core count} + 1, or you can specify number to use like -j8.

#### Setup ramdisk_mq

```bash
modprobe ramdisk_mq queue_mode={x} nr_hw_queues={y} hw_queue_depth={z} ramdisk_mq_size={w}
```

queue mode: 0-bio, 1-single queue, 2-multi queue

nr_hw_queues: number of queues

hw_queue_depth: depth of queue

ramdisk_mq_size: size of ramdisk_mq in bytes


Then you can find ramdisk_mq in /dev/ramdisk_mq.


## Developer Guide

We eliminate critical bugs and porting the kernel version from 4.4 to 5.0 on mybrd code which merged ramdisk and block layer mutli queue referenced by null_blk, brd and blk-mq.

You can reference : https://github.com/gurugio/mybrd/



## Publication

윤명식, 김성곤, 주용수, 임성수, "다중 큐 블록 계층을 이용하는 RAM 기반 블록 디바이스 구현"

