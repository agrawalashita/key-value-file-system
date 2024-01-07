/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * logfs.c
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "device.h"
#include "logfs.h"

#define WCACHE_BLOCKS 32
#define RCACHE_BLOCKS 256

#define _POSIX_C_SOURCE 200112L

/**
 * Needs:
 *   pthread_create()
 *   pthread_join()
 *   pthread_mutex_init()
 *   pthread_mutex_destroy()
 *   pthread_mutex_lock()
 *   pthread_mutex_unlock()
 *   pthread_cond_init()
 *   pthread_cond_destroy()
 *   pthread_cond_wait()
 *   pthread_cond_signal()
 */

/* research the above Needed API and design accordingly */

/**
 * Opens the block device specified in pathname for buffered I/O using an
 * append only log structure.
 *
 * pathname: the pathname of the block device
 *
 * return: an opaque handle or NULL on error
 */

#define QUEUE_SIZE 1024 * 1024 /* 1MB */

char queue[QUEUE_SIZE];
uint64_t tail = 0, head = 0, queue_size_occupied = 0;
int8_t stop_flushing_to_disk = 0;

struct cache {
    uint8_t valid;
    uint64_t offset;
    char *block;
} cache[RCACHE_BLOCKS];

pthread_t flush_thread;
pthread_mutex_t mutex, flush_mutex;
pthread_cond_t cond;

struct logfs {
    struct device *device;
    uint64_t device_offset;
    uint64_t device_block_size;
};

int flush_to_device(struct logfs *logfs, uint64_t len) {
    int remainingLen = len;
    uint64_t bytes_copied = 0, local_tail = tail;
    long size_to_write = len % logfs->device_block_size == 0 ? len : len + logfs->device_block_size - len % logfs->device_block_size;
    char *buf;

    if (len == 0) return 0;

    if (posix_memalign(&buf, logfs->device_block_size, size_to_write) != 0) {
        TRACE("allocate buffer with posix memalign");
        return 1;
    }
    memset(buf, 0, size_to_write);

    if (head <= local_tail && local_tail + len > QUEUE_SIZE) {
        bytes_copied = QUEUE_SIZE - local_tail;
        remainingLen -= bytes_copied;
        memcpy(buf, &queue[local_tail], bytes_copied);
        local_tail = 0;
    }

    memcpy(buf + bytes_copied, &queue[local_tail], remainingLen);
    local_tail += remainingLen;

    if (device_write(logfs->device, buf, logfs->device_offset, size_to_write)) {
        TRACE("device write");
        return 1;
    }

    if (len % logfs->device_block_size == 0) {
        logfs->device_offset += len;
        tail = local_tail;
        queue_size_occupied -= len;
    }

    FREE(buf);

    return 0;
}

void *flush(void *logfs_arg) {
    struct logfs *logfs = (struct logfs *) logfs_arg;

    while (1) {
        int queue_size_to_flush;

        pthread_mutex_lock(&mutex);

        while (!stop_flushing_to_disk && queue_size_occupied < logfs->device_block_size) {
            pthread_cond_wait(&cond, &mutex);
        }

        /* If last flush remaining queue else as many blocks as we can fit */
        queue_size_to_flush = stop_flushing_to_disk ? queue_size_occupied : (queue_size_occupied / logfs->device_block_size) * logfs->device_block_size;

        if (flush_to_device(logfs, queue_size_to_flush)) {
            TRACE("flushing to device");
            logfs_close(logfs);
            exit(0);
        }

        pthread_cond_signal(&cond);

        pthread_mutex_unlock(&mutex);

        if (stop_flushing_to_disk) {
            break;
        }
    }
    return NULL;
}

/**
 * Opens the block device specified in pathname for buffered I/O using an
 * append only log structure.
 *
 * pathname: the pathname of the block device
 *
 * return: an opaque handle or NULL on error
 */

struct logfs *logfs_open(const char *pathname) {
    struct logfs *logfs;
    int i;

    if ((logfs = malloc(sizeof(struct logfs))) == NULL) {
        TRACE("logfs malloc");
        return NULL;
    }

    if ((logfs->device = device_open(pathname)) == NULL) {
        TRACE("device open");
        free(logfs);
        return NULL;
    }

    logfs->device_offset = 0;
    logfs->device_block_size = device_block(logfs->device);

    /* setup cache */

    memset(cache, 0, sizeof(cache));

    for (i = 0; i < RCACHE_BLOCKS; i++) {
        if ((cache[i].block = (char *)malloc(logfs->device_block_size)) == NULL) {
            TRACE("cache block malloc");
            return NULL;
        }
    }

    pthread_mutex_init(&mutex, NULL);
    pthread_mutex_init(&flush_mutex, NULL);
    pthread_cond_init(&cond, NULL);

    pthread_create(&flush_thread, NULL, flush, (void *)logfs);

    us_sleep(10);

    return logfs;
}

void reset_queue() {
    tail = 0, head = 0, queue_size_occupied = 0, stop_flushing_to_disk = 0;
    memset(queue, 0, QUEUE_SIZE);
}

/**
 * Closes a previously opened logfs handle.
 *
 * logfs: an opaque handle previously obtained by calling logfs_open()
 *
 * Note: logfs may be NULL.
 */

void logfs_close(struct logfs *logfs) {
    int i;

    /* signal the flush thread to stop */
    pthread_mutex_lock(&flush_mutex);
    stop_flushing_to_disk = 1;
    pthread_mutex_unlock(&flush_mutex);
    pthread_cond_signal(&cond);

    pthread_join(flush_thread, NULL);

    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&flush_mutex);
    pthread_cond_destroy(&cond);

    for (i = 0; i < RCACHE_BLOCKS; i++) {
        FREE(cache[i].block);
    }

    reset_queue();
    device_close(logfs->device);
    FREE(logfs);
}

long cache_block_mapping(uint64_t read_offset, uint64_t block_size) {
    return (read_offset / block_size) % RCACHE_BLOCKS;
}

int try_cache_read(struct logfs *logfs, void *buf, uint64_t off, size_t len) {
    uint64_t bytes_unread = off % logfs->device_block_size;
    uint64_t bytes_to_read;
    uint64_t read_offset = bytes_unread > 0 ? off - bytes_unread : off;
    uint64_t read_into_buf = 0;
    long cache_block = cache_block_mapping(read_offset, logfs->device_block_size);
    char *read_buf;

    if (cache[cache_block].valid && cache[cache_block].offset == read_offset) {
        int data_in_cache = 1;

        read_buf = cache[cache_block].block;

        bytes_to_read = off + len > read_offset + logfs->device_block_size ? logfs->device_block_size - bytes_unread : len;
        memcpy(buf, read_buf + bytes_unread, bytes_to_read);
        read_into_buf += bytes_to_read;

        read_offset += logfs->device_block_size;

        /* copy remaining blocks if any */
        while (off + len > read_offset) {
            bytes_to_read = off + len < read_offset + logfs->device_block_size ? off + len - read_offset : logfs->device_block_size; 

            /* break if next block not found in cache */
            cache_block = cache_block_mapping(read_offset, logfs->device_block_size);
            if (!(cache[cache_block].valid && cache[cache_block].offset == read_offset)) {
                data_in_cache = 0;
                break;
            }

            read_buf = cache[cache_block].block;

            memcpy((void *)((long) buf + read_into_buf), read_buf, bytes_to_read);
            read_into_buf += bytes_to_read;

            read_offset += logfs->device_block_size;
        }

        /* return if data found in cache else read from disk */
        if (data_in_cache) return 0;
    }
    
    return 1;
}

/**
 * Random read of len bytes at location specified in off from the logfs.
 *
 * logfs: an opaque handle previously obtained by calling logfs_open()
 * buf  : a region of memory large enough to receive len bytes
 * off  : the starting byte offset
 * len  : the number of bytes to read
 *
 * return: 0 on success, otherwise error
 */

int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len) {
    uint64_t bytes_unread = off % logfs->device_block_size;
    uint64_t bytes_to_read;
    uint64_t read_offset = bytes_unread > 0 ? off - bytes_unread : off;
    uint64_t read_into_buf = 0;
    char *read_buf;

    /* cache hit for all blocks*/
    if (!try_cache_read(logfs, buf, off, len)) {
        return 0;
    }

    /* cache miss */

    /* allocate read buffer */
    if (posix_memalign(&read_buf, logfs->device_block_size, logfs->device_block_size) != 0) {
        TRACE("allocate read buffer with posix memalign");
        logfs_close(logfs);
        return 1;
    }
    memset(read_buf, 0, logfs->device_block_size);
        
    /* copy first block*/
    if (device_read(logfs->device, read_buf, read_offset, logfs->device_block_size)) {
        TRACE("logfs device read first block");
        return 1;
    }

    bytes_to_read = off + len > read_offset + logfs->device_block_size ? logfs->device_block_size - bytes_unread : len;
    memcpy(buf, read_buf + bytes_unread, bytes_to_read);
    read_into_buf += bytes_to_read;

    read_offset += logfs->device_block_size;

    /* copy remaining blocks if any */
    while (off + len > read_offset) {
        bytes_to_read = off + len < read_offset + logfs->device_block_size ? off + len - read_offset : logfs->device_block_size; 

        if (device_read(logfs->device, read_buf, read_offset, logfs->device_block_size)) {
            TRACE("logfs device read subsequent blocks");
            return 1;
        }

        memcpy((void *)((long) buf + read_into_buf), read_buf, bytes_to_read);
        read_into_buf += bytes_to_read;

        read_offset += logfs->device_block_size;
    }

    FREE(read_buf);

    return 0;
}

void update_cache(char *read_buf, uint64_t read_offset, uint64_t block_size) {
    long cache_block = cache_block_mapping(read_offset, block_size);
    cache[cache_block].valid = 1;
    cache[cache_block].offset = read_offset;
    memcpy(cache[cache_block].block, read_buf, block_size);
}

int update_cache_after_write(struct logfs *logfs, uint64_t len) {
    int remainingLen = len;
    uint64_t bytes_copied = 0, local_tail = tail;
    long buf_size = len % logfs->device_block_size == 0 ? len : len + logfs->device_block_size - len % logfs->device_block_size;
    long buf_offset = 0;
    long cache_device_offset = logfs->device_offset;
    char *buf;

    if ((buf = malloc(buf_size)) == NULL) {
        TRACE("buf malloc for caching");
        return 1;
    }

    if (head <= local_tail && local_tail + len > QUEUE_SIZE) {
        bytes_copied = QUEUE_SIZE - local_tail;
        remainingLen -= bytes_copied;
        memcpy(buf, &queue[local_tail], bytes_copied);
        local_tail = 0;
    }

    memcpy(buf + bytes_copied, &queue[local_tail], remainingLen);
    local_tail += remainingLen;

    while (buf_size) {
        update_cache(buf + buf_offset, cache_device_offset, logfs->device_block_size);

        buf_offset += logfs->device_block_size;
        cache_device_offset += logfs->device_block_size;
        buf_size -= logfs->device_block_size;
    }

    FREE(buf);

    return 0;
}

/**
 * Append len bytes to the logfs.
 *
 * logfs: an opaque handle previously obtained by calling logfs_open()
 * buf  : a region of memory holding the len bytes to be written
 * len  : the number of bytes to write
 *
 * return: 0 on success, otherwise error
 */
int logfs_append(struct logfs *logfs, const void *buf, uint64_t len) {
    int remainingLen = len;
    long bytes_copied = 0;

    pthread_mutex_lock(&mutex);

    /* wait if queue is full*/
    while (queue_size_occupied + len > QUEUE_SIZE) {
        pthread_cond_wait(&cond, &mutex);
    }

    /* queue wrap around */
    if (head >= tail && head + len > QUEUE_SIZE) {
        bytes_copied = QUEUE_SIZE - head;
        remainingLen -= bytes_copied;
        memcpy(&queue[head], buf, bytes_copied);
        head = 0;
    }

    memcpy(&queue[head], (char *)buf + bytes_copied, remainingLen);

    head += remainingLen;
    queue_size_occupied += len;

    /* update cache */
    if (update_cache_after_write(logfs, queue_size_occupied)) {
        TRACE("updating cache after write to queue");
        return 1;
    }

    pthread_cond_signal(&cond);
    
    pthread_mutex_unlock(&mutex);

    return 0;
}