/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Filesystem device abstraction layer
 */

#ifndef SPDK_FSDEV_H
#define SPDK_FSDEV_H

#include "spdk/stdinc.h"
#include "spdk/json.h"
#include "spdk/assert.h"
#include "spdk/dma.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief SPDK filesystem device.
 *
 * This is a virtual representation of a filesystem device that is exported by the backend.
 */
struct spdk_fsdev;

/** Asynchronous event type */
enum spdk_fsdev_event_type {
	SPDK_FSDEV_EVENT_REMOVE,
};

/**
 * Filesystem device event callback.
 *
 * \param type Event type.
 * \param fsdev Filesystem device that triggered event.
 * \param event_ctx Context for the filesystem device event.
 */
typedef void (*spdk_fsdev_event_cb_t)(enum spdk_fsdev_event_type type,
				      struct spdk_fsdev *fsdev,
				      void *event_ctx);

struct spdk_fsdev_fn_table;
struct spdk_io_channel;

/** fsdev status */
enum spdk_fsdev_status {
	SPDK_FSDEV_STATUS_INVALID,
	SPDK_FSDEV_STATUS_READY,
	SPDK_FSDEV_STATUS_UNREGISTERING,
	SPDK_FSDEV_STATUS_REMOVING,
};

/** fsdev library options */
struct spdk_fsdev_opts {
	/**
	 * The size of spdk_fsdev_opts according to the caller of this library is used for ABI
	 * compatibility.  The library uses this field to know how many fields in this
	 * structure are valid. And the library will populate any remaining fields with default values.
	 * New added fields should be put at the end of the struct.
	 */
	uint32_t opts_size;
	/**
	 * Size of fsdev IO objects pool
	 */
	uint32_t fsdev_io_pool_size;
	/**
	 * Size of fsdev IO objects cache per thread
	 */
	uint32_t fsdev_io_cache_size;
} __attribute__((packed));
SPDK_STATIC_ASSERT(sizeof(struct spdk_fsdev_opts) == 12, "Incorrect size");

/** fsdev mount options */
struct spdk_fsdev_mount_opts {
	/**
	 * The size of spdk_fsdev_mount_opts according to the caller of this library is used for ABI
	 * compatibility.  The library uses this field to know how many fields in this
	 * structure are valid. And the library will populate any remaining fields with default values.
	 * New added fields should be put at the end of the struct.
	 */
	uint32_t opts_size;

	/**
	 * OUT Maximum size of the write buffer
	 */
	uint32_t max_write;

	/**
	 * IN/OUT Indicates whether the writeback caching should be enabled.
	 *
	 * See FUSE I/O ([1]) doc for more info.
	 *
	 * [1] https://www.kernel.org/doc/Documentation/filesystems/fuse-io.txt
	 *
	 * This feature is disabled by default.
	 */
	uint8_t writeback_cache_enabled;

} __attribute__((packed));
SPDK_STATIC_ASSERT(sizeof(struct spdk_fsdev_mount_opts) == 9, "Incorrect size");

/**
 * Structure with optional fsdev IO parameters
 * The content of this structure must be valid until the IO is completed
 */
struct spdk_fsdev_io_opts {
	/** Size of this structure in bytes */
	size_t size;
	/** Memory domain which describes payload in this IO. fsdev must support DMA device type that
	 * can access this memory domain, refer to \ref spdk_fsdev_get_memory_domains and
	 * \ref spdk_memory_domain_get_dma_device_type
	 * If set, that means that data buffers can't be accessed directly and the memory domain must
	 * be used to fetch data to local buffers or to translate data to another memory domain */
	struct spdk_memory_domain *memory_domain;
	/** Context to be passed to memory domain operations */
	void *memory_domain_ctx;
} __attribute__((packed));
SPDK_STATIC_ASSERT(sizeof(struct spdk_fsdev_io_opts) == 24, "Incorrect size");

/**
 * \brief Handle to an opened SPDK filesystem device.
 */
struct spdk_fsdev_desc;

/**
 * Filesystem device initialization callback.
 *
 * \param cb_arg Callback argument.
 * \param rc 0 if filesystem device initialized successfully or negative errno if it failed.
 */
typedef void (*spdk_fsdev_init_cb)(void *cb_arg, int rc);

/**
 * Filesystem device finish callback.
 *
 * \param cb_arg Callback argument.
 */
typedef void (*spdk_fsdev_fini_cb)(void *cb_arg);

/**
 * Initialize filesystem device modules.
 *
 * \param cb_fn Called when the initialization is complete.
 * \param cb_arg Argument passed to function cb_fn.
 */
void spdk_fsdev_initialize(spdk_fsdev_init_cb cb_fn, void *cb_arg);

/**
 * Perform cleanup work to remove the registered filesystem device modules.
 *
 * \param cb_fn Called when the removal is complete.
 * \param cb_arg Argument passed to function cb_fn.
 */
void spdk_fsdev_finish(spdk_fsdev_fini_cb cb_fn, void *cb_arg);

/**
 * Get the full configuration options for the registered filesystem device modules and created fsdevs.
 *
 * \param w pointer to a JSON write context where the configuration will be written.
 */
void spdk_fsdev_subsystem_config_json(struct spdk_json_write_ctx *w);

/**
 * Get filesystem device module name.
 *
 * \param fsdev Filesystem device to query.
 * \return Name of fsdev module as a null-terminated string.
 */
const char *spdk_fsdev_get_module_name(const struct spdk_fsdev *fsdev);

/**
 * Open a filesystem device for I/O operations.
 *
 * \param fsdev_name Filesystem device name to open.
 * \param event_cb notification callback to be called when the fsdev triggers
 * asynchronous event such as fsdev removal. This will always be called on the
 * same thread that spdk_fsdev_open() was called on. In case of removal event
 * the descriptor will have to be manually closed to make the fsdev unregister
 * proceed.
 * \param event_ctx param for event_cb.
 * \param desc output parameter for the descriptor when operation is successful
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int spdk_fsdev_open(const char *fsdev_name, spdk_fsdev_event_cb_t event_cb,
		    void *event_ctx, struct spdk_fsdev_desc **desc);

/**
 * Close a previously opened filesystem device.
 *
 * Must be called on the same thread that the spdk_fsdev_open()
 * was performed on.
 *
 * \param desc Filesystem device descriptor to close.
 */
void spdk_fsdev_close(struct spdk_fsdev_desc *desc);

/**
 * Callback function for spdk_for_each_fsdev().
 *
 * \param ctx Context passed to the callback.
 * \param fsdev filesystem device the callback handles.
 */
typedef int (*spdk_for_each_fsdev_fn)(void *ctx, struct spdk_fsdev *fsdev);

/**
 * Call the provided callback function for every registered filesystem device.
 * If fn returns negated errno, spdk_for_each_fsdev() terminates iteration.
 *
 * spdk_for_each_fsdev() opens before and closes after executing the provided
 * callback function for each fsdev internally.
 *
 * \param ctx Context passed to the callback function.
 * \param fn Callback function for each filesystem device.
 *
 * \return 0 if operation is successful, or suitable errno value one of the
 * callback returned otherwise.
 */
int spdk_for_each_fsdev(void *ctx, spdk_for_each_fsdev_fn fn);

/**
 * Get filesystem device name.
 *
 * \param fsdev filesystem device to query.
 * \return Name of fsdev as a null-terminated string.
 */
const char *spdk_fsdev_get_name(const struct spdk_fsdev *fsdev);

/**
 * Get the fsdev associated with a fsdev descriptor.
 *
 * \param desc Open filesystem device descriptor
 * \return fsdev associated with the descriptor
 */
struct spdk_fsdev *spdk_fsdev_desc_get_fsdev(struct spdk_fsdev_desc *desc);

/**
 * Obtain an I/O channel for the filesystem device opened by the specified
 * descriptor. I/O channels are bound to threads, so the resulting I/O
 * channel may only be used from the thread it was originally obtained
 * from.
 *
 * \param desc Filesystem device descriptor.
 *
 * \return A handle to the I/O channel or NULL on failure.
 */
struct spdk_io_channel *spdk_fsdev_get_io_channel(struct spdk_fsdev_desc *desc);

/**
 * Set the options for the fsdev library.
 *
 * \param opts options to set
 * \return 0 on success.
 * \return -EINVAL if the options are invalid.
 */
int spdk_fsdev_set_opts(const struct spdk_fsdev_opts *opts);

/**
 * Get the options for the fsdev library.
 *
 * \param opts Output parameter for options.
 * \param opts_size sizeof(*opts)
 */
int spdk_fsdev_get_opts(struct spdk_fsdev_opts *opts, size_t opts_size);

/**
 * Get SPDK memory domains used by the given fsdev. If fsdev reports that it uses memory domains
 * that means that it can work with data buffers located in those memory domains.
 *
 * The user can call this function with \b domains set to NULL and \b array_size set to 0 to get the
 * number of memory domains used by fsdev
 *
 * \param fsdev filesystem device
 * \param domains pointer to an array of memory domains to be filled by this function. The user should allocate big enough
 * array to keep all memory domains used by fsdev and all underlying fsdevs
 * \param array_size size of \b domains array
 * \return the number of entries in \b domains array or negated errno. If returned value is bigger than \b array_size passed by the user
 * then the user should increase the size of \b domains array and call this function again. There is no guarantees that
 * the content of \b domains array is valid in that case.
 *         -EINVAL if input parameters were invalid
 */
int spdk_fsdev_get_memory_domains(struct spdk_fsdev *fsdev, struct spdk_memory_domain **domains,
				  int array_size);

/**
 * Output driver-specific information to a JSON stream.
 *
 * The JSON write context will be initialized with an open object, so the fsdev
 * driver should write a name (based on the driver name) followed by a JSON value
 * (most likely another nested object).
 *
 * \param fsdev Filesystem to query.
 * \param w JSON write context. It will store the driver-specific configuration context.
 * \return 0 on success, negated errno on failure.
 */
int spdk_fsdev_dump_info_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w);

/**
 * \brief SPDK fsdev channel iterator.
 *
 * This is a virtual representation of a fsdev channel iterator.
 */
struct spdk_fsdev_channel_iter;

/**
 * Called on the appropriate thread for each channel associated with the given fsdev.
 *
 * \param i fsdev channel iterator.
 * \param fsdev filesystem device.
 * \param ch I/O channel.
 * \param ctx context of the fsdev channel iterator.
 */
typedef void (*spdk_fsdev_for_each_channel_msg)(struct spdk_fsdev_channel_iter *i,
		struct spdk_fsdev *fsdev, struct spdk_io_channel *ch, void *ctx);

/**
 * spdk_fsdev_for_each_channel() function's final callback with the given fsdev.
 *
 * \param fsdev filesystem device.
 * \param ctx context of the fsdev channel iterator.
 * \param status 0 if it completed successfully, or negative errno if it failed.
 */
typedef void (*spdk_fsdev_for_each_channel_done)(struct spdk_fsdev *fsdev, void *ctx, int status);

/**
 * Helper function to iterate the next channel for spdk_fsdev_for_each_channel().
 *
 * \param i fsdev channel iterator.
 * \param status Status for the fsdev channel iterator;
 * for non 0 status remaining iterations are terminated.
 */
void spdk_fsdev_for_each_channel_continue(struct spdk_fsdev_channel_iter *i, int status);

/**
 * Call 'fn' on each channel associated with the given fsdev.
 *
 * This happens asynchronously, so fn may be called after spdk_fsdev_for_each_channel
 * returns. 'fn' will be called for each channel serially, such that two calls
 * to 'fn' will not overlap in time. After 'fn' has been called, call
 * spdk_fsdev_for_each_channel_continue() to continue iterating. Note that the
 * spdk_fsdev_for_each_channel_continue() function can be called asynchronously.
 *
 * \param fsdev 'fn' will be called on each channel associated with this given fsdev.
 * \param fn Called on the appropriate thread for each channel associated with the given fsdev.
 * \param ctx Context for the caller.
 * \param cpl Called on the thread that spdk_fsdev_for_each_channel was initially called
 * from when 'fn' has been called on each channel.
 */
void spdk_fsdev_for_each_channel(struct spdk_fsdev *fsdev, spdk_fsdev_for_each_channel_msg fn,
				 void *ctx, spdk_fsdev_for_each_channel_done cpl);

/**
 * Filesystem device reset completion callback.
 *
 * \param desc Filesystem device descriptor.
 * \param success True if reset completed successfully or false if it failed.
 * \param cb_arg Callback argument specified upon reset operation.
 */
typedef void (*spdk_fsdev_reset_completion_cb)(struct spdk_fsdev_desc *desc, bool success,
		void *cb_arg);

/**
 * Issue reset operation to the fsdev.
 *
 * \param desc Filesystem device descriptor.
 * \param cb Called when the reset is complete.
 * \param cb_arg Argument passed to cb.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 */
int spdk_fsdev_reset(struct spdk_fsdev_desc *desc, spdk_fsdev_reset_completion_cb cb, void *cb_arg);

/**
 * Check whether the Filesystem device supports reset.
 *
 * \param fsdev Filesystem device to check.
 * \return true if support, false otherwise.
 */
bool spdk_fsdev_reset_supported(struct spdk_fsdev *fsdev);

/* 'to_set' flags in spdk_fsdev_setattr */
#define FSDEV_SET_ATTR_MODE	(1 << 0)
#define FSDEV_SET_ATTR_UID	(1 << 1)
#define FSDEV_SET_ATTR_GID	(1 << 2)
#define FSDEV_SET_ATTR_SIZE	(1 << 3)
#define FSDEV_SET_ATTR_ATIME	(1 << 4)
#define FSDEV_SET_ATTR_MTIME	(1 << 5)
#define FSDEV_SET_ATTR_ATIME_NOW	(1 << 6)
#define FSDEV_SET_ATTR_MTIME_NOW	(1 << 7)
#define FSDEV_SET_ATTR_CTIME	(1 << 8)

struct spdk_fsdev_file_object;
struct spdk_fsdev_file_handle;

struct spdk_fsdev_file_attr {
	uint64_t ino;
	uint64_t size;
	uint64_t blocks;
	uint64_t atime;
	uint64_t mtime;
	uint64_t ctime;
	uint32_t atimensec;
	uint32_t mtimensec;
	uint32_t ctimensec;
	uint32_t mode;
	uint32_t nlink;
	uint32_t uid;
	uint32_t gid;
	uint32_t rdev;
	uint32_t blksize;
	uint32_t valid_ms;
};

struct spdk_fsdev_file_statfs {
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t files;
	uint64_t ffree;
	uint32_t bsize;
	uint32_t namelen;
	uint32_t frsize;
};

/* Resembling file lock types. */
enum spdk_fsdev_file_lock_type {
	SPDK_FSDEV_RDLCK = 0,
	SPDK_FSDEV_WRLCK = 1,
	SPDK_FSDEV_UNLCK = 2
};

/* Resembling flock operation type */
enum spdk_fsdev_file_lock_op {
	/*
	 * Place a shared lock. More than one process may hold
	 * a shared lock for a given file at a given time.
	 */
	SPDK_FSDEV_LOCK_SH = 0,

	/*
	 * Place an exclusive lock.  Only one process may hold
	 * an exclusive lock for a given file at a given time.
	 */
	SPDK_FSDEV_LOCK_EX = 1,

	/* Remove an existing lock held by this process. */
	SPDK_FSDEV_LOCK_UN = 2
};

/*
 * This structure provides the info/description on/of a specific file lock
 * and is used for delivering the lock params to and from the fsdev API and
 * the lower layers.
 */
struct spdk_fsdev_file_lock {
	/* SPDK variant of F_RDLCK. F_WRLCK, F_UNLCK */
	enum spdk_fsdev_file_lock_type type;

	/* Starting offset for lock */
	uint64_t start;

	/* End of the lock region in bytes */
	uint64_t end;

	/*
	 * Originally PID of process blocking our lock.
	 * In context of virtiofs this can be used for
	 * similar task but this needs to be taken care
	 * of specially. For now we have it here.
	 */
	uint32_t pid;
};

/*
 * Used for denoting the end of the file when specifying the
 * file lock params.
 */
#define SPDK_FSDEV_FILE_LOCK_END_OF_FILE LONG_MAX

/**
 * Mount operation completion callback.
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation status, 0 on success or error code otherwise.
 * \param opts Result options.
 * \param root_fobject Root file object
 */
typedef void (spdk_fsdev_mount_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
				       const struct spdk_fsdev_mount_opts *opts,
				       struct spdk_fsdev_file_object *root_fobject);

/**
 * Mount the filesystem.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param opts Requested options.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *
 * Note: the \p opts are the subject of negotiation. An API user provides a desired \p opts here
 * and gets a result \p opts in the \p cb_fn. The result \p opts are filled by the underlying
 * fsdev module which may agree or reduce (but not expand) the desired features set.
 */
int spdk_fsdev_mount(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		     uint64_t unique, const struct spdk_fsdev_mount_opts *opts,
		     spdk_fsdev_mount_cpl_cb cb_fn, void *cb_arg);

/**
 * Umount operation completion callback.
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 */
typedef void (spdk_fsdev_umount_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch);

/**
 * Unmount the filesystem.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 */
int spdk_fsdev_umount(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, spdk_fsdev_umount_cpl_cb cb_fn, void *cb_arg);

/**
 * Syncfs operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation status, 0 on success or error code otherwise.
 */
typedef void (spdk_fsdev_syncfs_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
					int status);

/**
 * Sync entire filesystem referred by the file handle.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object to identify the fs.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 */
int spdk_fsdev_syncfs(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, struct spdk_fsdev_file_object *fobject,
		      spdk_fsdev_syncfs_cpl_cb cb_fn, void *cb_arg);

/**
 * Lookup file operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fobject File object.
 * \param attr File attributes.
 */
typedef void (spdk_fsdev_lookup_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
					struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr);

/**
 * Look up a directory entry by name and get its attributes
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory. NULL for the root directory.
 * \param name The name to look up. Ignored if parent_fobject is NULL.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_lookup(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      struct spdk_fsdev_file_object *parent_fobject, const char *name,
		      spdk_fsdev_lookup_cpl_cb cb_fn, void *cb_arg);

/**
 * Access operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation status, 0 on success or error code otherwise.
 * \param mask Access mask to check.
 * \param uid Uid that was used for checking access.
 * \param gid Gid that was used for checking access.
 */
typedef void (spdk_fsdev_access_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
					int status, uint32_t mask, uid_t uid, uid_t gid);

/**
 * Check the file access flags for passed mask.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object for checking.
 * \param mask Access mask to check.
 * \param uid Uid to be used for checking access.
 * \param gid Gid to be used for checking access.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 * - -EACCESS - access is not allowed.
 */
int spdk_fsdev_access(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		      uint64_t unique, struct spdk_fsdev_file_object *fobject,
		      uint32_t mask, uid_t uid, uid_t gid, spdk_fsdev_access_cpl_cb cb_fn,
		      void *cb_arg);

/**
 * Look up file operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_forget_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Remove file object from internal cache
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param nlookup Number of lookups to forget.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_forget(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      struct spdk_fsdev_file_object *fobject, uint64_t nlookup,
		      spdk_fsdev_forget_cpl_cb cb_fn, void *cb_arg);

enum spdk_fsdev_seek_whence {
	SPDK_FSDEV_SEEK_SET = (1 << 0),
	SPDK_FSDEV_SEEK_CUR = (1 << 1),
	SPDK_FSDEV_SEEK_END = (1 << 2),
	SPDK_FSDEV_SEEK_HOLE = (1 << 3),
	SPDK_FSDEV_SEEK_DATA = (1 << 4)
};

/**
 * Reposition read/write file offset callback.
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation status, 0 on success or error code otherwise.
 * \param offset Resulting offset.
 * \param whence Used whence.
 */
typedef void (spdk_fsdev_lseek_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
				       int status, off_t offset, enum spdk_fsdev_seek_whence whence);

/**
 * Reposition read/write file offset operation.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param offset The offset is bytes.
 * \param whence Behavior of the offset usage.
 * - SPDK_FSDEV_SEEK_SET  - the offset is set to offset bytes.
 * - SPDK_FSDEV_SSEEK_CUR  - the offset is set to its current location plus offset bytes.
 * - SPDK_FSDEV_SSEEK_END  - the offset is set to the size of the file plus offset bytes.
 * - SPDK_FSDEV_SSEEK_HOLE - the offset is set to the start of the next hole greater than or
 *   equal to the supplied offset.
 * - SPDK_FSDEV_SSEEK_DATA - the offset is set to the start of the next non-hole file region
 *   greater than or equal to the supplied offset.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 */
int spdk_fsdev_lseek(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		     uint64_t unique, struct spdk_fsdev_file_object *fobject,
		     struct spdk_fsdev_file_handle *fhandle, off_t offset,
		     enum spdk_fsdev_seek_whence whence, spdk_fsdev_lseek_cpl_cb cb_fn,
		     void *cb_arg);

/* Poll operation type. */
enum spdk_fsdev_poll_event_type {
	/* Indicates that there is data to read (regular data). */
	SPDK_FSDEV_POLLIN     = 0x0001,

	/* Indicates that normal data (not out-of-band) can be read. */
	SPDK_FSDEV_POLLRDNORM = 0x0040,

	/* Indicates that priority data (out-of-band) can be read. */
	SPDK_FSDEV_POLLRDBAND = 0x0080,

	/* Indicates that high-priority data (such as out-of-band data) is available
	 * to read. */
	SPDK_FSDEV_POLLPRI    = 0x0002,

	/* Indicates that writing is possible without blocking. */
	SPDK_FSDEV_POLLOUT    = 0x0004,

	/* Equivalent to SPDK_FSDEV_POLLOUT; indicates that normal data can be written. */
	SPDK_FSDEV_POLLWRNORM = 0x0100,

	/* Indicates that priority data can be written. */
	SPDK_FSDEV_POLLWRBAND = 0x0200,

	/* Indicates that an error has occurred on the file descriptor (only
	 * returned in revents). */
	SPDK_FSDEV_POLLERR    = 0x0008,

	/* Indicates a hang-up on the file descriptor, such as a disconnected
	 * device (only returned in revents). */
	SPDK_FSDEV_POLLHUP    = 0x0010,

	/* Indicates that the file descriptor is invalid (only returned in revents). */
	SPDK_FSDEV_POLLNVAL   = 0x0020
};

/**
 * The poll operation callback. Delivers mask of the event type available.
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation status, 0 on success or error code otherwise.
 * \param revents Operation types available mask. See spdk_fsdev_poll_event_type.
 *
 * \returns the following:
 * -EAGAIN - no events available.
 * 0       - requested events available.
 * < 0     - any other errors.
 */
typedef void (spdk_fsdev_poll_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
				      int status, uint32_t revents);

/**
 * Check for some event on a file.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param events Events we are interested in. See spdk_fsdev_poll_event_type.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 */
int spdk_fsdev_poll(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		    uint64_t unique, struct spdk_fsdev_file_object *fobject,
		    struct spdk_fsdev_file_handle *fhandle, uint32_t events,
		    spdk_fsdev_poll_cpl_cb cb_fn, void *cb_arg);

/**
 * Read symbolic link operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param linkname symbolic link contents
 */
typedef void (spdk_fsdev_readlink_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
		const char *linkname);

/**
 * Read symbolic link
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_readlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			uint64_t unique, struct spdk_fsdev_file_object *fobject,
			spdk_fsdev_readlink_cpl_cb cb_fn, void *cb_arg);

/**
 * Create a symbolic link operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fobject File object.
 * \param attr File attributes.
 */
typedef void (spdk_fsdev_symlink_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
		struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr);

/**
 * Ioctl operation completion callback.
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation status:
 * - 0 on success
 * - -EAGAIN on retry request when ioctl misses some buffers to set/get the
 * data (see how the FUSE_IOCTL_RETRY is used).
 * - error code otherwise.
 * \param result Exact result code returned from ioctl implementation.
 * \param in_iov Array of iovec describing the data to bring in the next retry.
 * \param in_iovcnt Size of in_iov array.
 * \param out_iov Array of iovec describing the output data to send in the next retry.
 * \param out_iovcnt Size of out_iov array.
 */
typedef void (spdk_fsdev_ioctl_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
				       int status, int32_t result,
				       struct iovec *in_iov, uint32_t in_iovcnt,
				       struct iovec *out_iov, uint32_t out_iovcnt);

/**
 * Ioctl operation.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param request A device-dependent request cmd.
 * \param arg Operation argument.
 * \param in_iov Array of iovec with input data.
 * \param in_iovcnt Size of in_iov array.
 * \param out_iov Array of iovec for output data.
 * \param out_iovcnt Size of out_iov array.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 */
int spdk_fsdev_ioctl(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		     uint64_t unique, struct spdk_fsdev_file_object *fobject,
		     struct spdk_fsdev_file_handle *fhandle, uint32_t request,
		     void *arg, struct iovec *in_iov, uint32_t in_iovcnt,
		     struct iovec *out_iov, uint32_t out_iovcnt,
		     spdk_fsdev_ioctl_cpl_cb cb_fn, void *cb_arg);

/**
 * Getlk operation completion callback.
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status Operation status, 0 on success or error code otherwise.
 * \param lock Conflicting lock params.
 */
typedef void (spdk_fsdev_getlk_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
				       int status, const struct spdk_fsdev_file_lock *lock);

/**
 * This function checks if the lock with a particular params can be placed.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param lock_to_check The lock params to check for possible conflicting locks.
 * \param owner Used for lock ownership checks.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *
 * If the lock could be placed, the function does not actually place it, but
 * returns SPDK_FSDEV_UNLCK in the "type" field of lock and leaves the other
 * fields of the structure unchanged.
 *
 * If one or more incompatible locks would prevent this lock being placed, then
 * the function returns details about one of those locks in the "type", "start", and
 * "end" fields of lock. If the conflicting lock is a traditional (process-associated)
 * record lock, then the "pid" field is set to the PID of the process holding that lock.
 * If the conflicting lock is an open file de-scription lock, then "pid" is set to -1.
 * Note that the returned information may already be out of date by the time the caller
 * inspects it.
 */
int spdk_fsdev_getlk(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		     uint64_t unique, struct spdk_fsdev_file_object *fobject,
		     struct spdk_fsdev_file_handle *fhandle,
		     const struct spdk_fsdev_file_lock *lock_to_check,
		     uint64_t owner, spdk_fsdev_getlk_cpl_cb cb_fn, void *cb_arg);

/**
 * Setlk operation completion callback.
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_op_ API
 * \param ch I/O channel.
 * \param status Operation status, 0 on success or error code otherwise.
 */
typedef void (spdk_fsdev_setlk_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
				       int status);

/**
 * Setlk operation. Acquire, modify or release a file lock.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param lock_to_acquire Lock params we use to acquire the lock.
 * \param owner Used for lock ownership checks.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *
 * Acquire a lock (when "type" is SPDK_FSDEV_RDLCK or SPDK_FSDEV_WRLCK) or
 * release a lock (when "type" is SPDK_FSDEV_UNLCK) on the bytes specified
 * by the "start", and "end" fields of lock. If a conflicting lock is held
 * by another process, this call returns -EAGAIN.
 */
int spdk_fsdev_setlk(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		     uint64_t unique, struct spdk_fsdev_file_object *fobject,
		     struct spdk_fsdev_file_handle *fhandle,
		     const struct spdk_fsdev_file_lock *lock_to_acquire,
		     uint64_t owner, spdk_fsdev_setlk_cpl_cb cb_fn, void *cb_arg);

/**
 * Create a symbolic link
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory
 * \param target symbolic link's content
 * \param linkpath symbolic link's name
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_symlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		       struct spdk_fsdev_file_object *parent_fobject, const char *target,
		       const char *linkpath, uid_t euid, gid_t egid,
		       spdk_fsdev_symlink_cpl_cb cb_fn, void *cb_arg);

/**
 * Create file node operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fobject File object.
 * \param attr File attributes.
 */
typedef void (spdk_fsdev_mknod_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
				       struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr);

/**
 * Create file node
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory
 * \param name File name to create.
 * \param mode File type and mode with which to create the new file.
 * \param rdev The device number (only valid if created file is a device)
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_mknod(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode, dev_t rdev,
		     uid_t euid, gid_t egid, spdk_fsdev_mknod_cpl_cb cb_fn, void *cb_arg);

/**
 * Create a directory operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fobject File object.
 * \param attr File attributes.
 */
typedef void (spdk_fsdev_mkdir_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
				       struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr);

/**
 * Create a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory
 * \param name Directory name to create.
 * \param mode Directory type and mode with which to create the new directory.
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_mkdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode,
		     uid_t euid, gid_t egid, spdk_fsdev_mkdir_cpl_cb cb_fn, void *cb_arg);


/**
 * Remove a file operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_unlink_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Remove a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory
 * \param name Name to remove.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_unlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      struct spdk_fsdev_file_object *parent_fobject, const char *name,
		      spdk_fsdev_unlink_cpl_cb cb_fn, void *cb_arg);

/**
 * Remove a directory operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_rmdir_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Remove a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory
 * \param name Name to remove.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_rmdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *parent_fobject, const char *name,
		     spdk_fsdev_rmdir_cpl_cb cb_fn, void *cb_arg);

/**
 * Rename a file operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_rename_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Rename a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory.
 * \param name Old rename.
 * \param new_parent_fobject New parent directory.
 * \param new_name New name.
 * \param flags Operation flags.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_rename(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      struct spdk_fsdev_file_object *parent_fobject, const char *name,
		      struct spdk_fsdev_file_object *new_parent_fobject, const char *new_name,
		      uint32_t flags, spdk_fsdev_rename_cpl_cb cb_fn, void *cb_arg);

/**
 * Create a hard link operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fobject File object.
 * \param attr File attributes.
 */
typedef void (spdk_fsdev_link_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
				      struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr);

/**
 * Create a hard link
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param new_parent_fobject New parent directory.
 * \param name Link name.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_link(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_object *new_parent_fobject,
		    const char *name, spdk_fsdev_link_cpl_cb cb_fn, void *cb_arg);

/**
 * Get file system statistic operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param statfs filesystem statistics
 */
typedef void (spdk_fsdev_statfs_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
					const struct spdk_fsdev_file_statfs *statfs);

/**
 * Get file system statistics
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_statfs(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      struct spdk_fsdev_file_object *fobject, spdk_fsdev_statfs_cpl_cb cb_fn, void *cb_arg);

/**
 * Set an extended attribute operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_setxattr_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Set an extended attribute
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param name Name of an extended attribute.
 * \param value Buffer that contains value of an extended attribute.
 * \param size Size of an extended attribute.
 * \param flags Operation flags.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_setxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			uint64_t unique, struct spdk_fsdev_file_object *fobject, const char *name, const char *value,
			size_t size, uint32_t flags, spdk_fsdev_setxattr_cpl_cb cb_fn, void *cb_arg);
/**
 * Get an extended attribute operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param value_size Size of an data copied to the value buffer.
 */
typedef void (spdk_fsdev_getxattr_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
		size_t value_size);

/**
 * Get an extended attribute
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param name Name of an extended attribute.
 * \param buffer Buffer to put the extended attribute's value.
 * \param size Size of value's buffer.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_getxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			uint64_t unique, struct spdk_fsdev_file_object *fobject, const char *name, void *buffer,
			size_t size, spdk_fsdev_getxattr_cpl_cb cb_fn, void *cb_arg);

/**
 * List extended attribute names operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param size Size of an extended attribute list.
 * \param size_only true if buffer was NULL or size was 0 upon the \ref spdk_fsdev_listxattr call
 */
typedef void (spdk_fsdev_listxattr_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
		size_t size, bool size_only);

/**
 * List extended attribute names
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param buffer Buffer to to be used for the attribute names.
 * \param size Size of the \b buffer.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_listxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			 uint64_t unique, struct spdk_fsdev_file_object *fobject, char *buffer, size_t size,
			 spdk_fsdev_listxattr_cpl_cb cb_fn, void *cb_arg);

/**
 * Remove an extended attribute operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_removexattr_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
		int status);

/**
 * Remove an extended attribute
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param name Name of an extended attribute.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_removexattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			   uint64_t unique, struct spdk_fsdev_file_object *fobject, const char *name,
			   spdk_fsdev_removexattr_cpl_cb cb_fn, void *cb_arg);

/**
 * Open a file operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fhandle File handle
 */
typedef void (spdk_fsdev_fopen_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
				       struct spdk_fsdev_file_handle *fhandle);

/**
 * Open a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param flags Operation flags.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_fopen(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *fobject, uint32_t flags, spdk_fsdev_fopen_cpl_cb cb_fn,
		     void *cb_arg);


/**
 * Create and open a file operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param fobject File object.
 * \param attr File attributes.
 * \param fhandle File handle.
 */
typedef void (spdk_fsdev_create_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
					struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
					struct spdk_fsdev_file_handle *fhandle);

/**
 * Create and open a file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param parent_fobject Parent directory
 * \param name Name to create.
 * \param mode File type and mode with which to create the new file.
 * \param flags Operation flags.
 * \param umask Umask of the calling process.
 * \param euid Effective user ID of the calling process.
 * \param egid Effective group ID of the calling process.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 *  -ENOMEM - operation cannot be initiated as a buffer cannot be allocated
 */
int spdk_fsdev_create(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode, uint32_t flags,
		      mode_t umask, uid_t euid, gid_t egid,
		      spdk_fsdev_create_cpl_cb cb_fn, void *cb_arg);

/**
 * Release an open file operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_release_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Release an open file
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_release(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		       struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		       spdk_fsdev_release_cpl_cb cb_fn, void *cb_arg);

/**
 * Get file attributes operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param attr file attributes.
 */
typedef void (spdk_fsdev_getattr_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_file_attr *attr);

/**
 * Get file attributes
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_getattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		       spdk_fsdev_getattr_cpl_cb cb_fn, void *cb_arg);

/**
 * Set file attributes operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status Operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param attr file attributes.
 */
typedef void (spdk_fsdev_setattr_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
		const struct spdk_fsdev_file_attr *attr);

/**
 * Set file attributes
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle
 * \param attr file attributes to set.
 * \param to_set Bit mask of attributes which should be set.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_setattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		       struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		       const struct spdk_fsdev_file_attr *attr, uint32_t to_set,
		       spdk_fsdev_setattr_cpl_cb cb_fn, void *cb_arg);

/**
 * Read data operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param data_size Number of bytes read.
 */
typedef void (spdk_fsdev_read_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
				      uint32_t data_size);

/**
 * Read data
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param size Number of bytes to read.
 * \param offs Offset to read from.
 * \param flags Operation flags.
 * \param iov Array of iovec to be used for the data.
 * \param iovcnt Size of the \b iov array.
 * \param opts Optional structure with extended File Operation options. If set, this structure must be
 * valid until the operation is completed. `size` member of this structure is used for ABI compatibility and
 * must be set to sizeof(struct spdk_fsdev_io_opts).
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_read(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		    size_t size, uint64_t offs, uint32_t flags,
		    struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_io_opts *opts,
		    spdk_fsdev_read_cpl_cb cb_fn, void *cb_arg);

/**
 * Write data operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param data_size Number of bytes written.
 */
typedef void (spdk_fsdev_write_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
				       uint32_t data_size);

/**
 * Write data
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param size Number of bytes to write.
 * \param offs Offset to write to.
 * \param flags Operation flags.
 * \param iov Array of iovec to where the data is stored.
 * \param iovcnt Size of the \b iov array.
 * \param opts Optional structure with extended File Operation options. If set, this structure must be
 * valid until the operation is completed. `size` member of this structure is used for ABI compatibility and
 * must be set to sizeof(struct spdk_fsdev_io_opts).
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_write(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle, size_t size,
		     uint64_t offs, uint64_t flags,
		     const struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_io_opts *opts,
		     spdk_fsdev_write_cpl_cb cb_fn, void *cb_arg);

/**
 * Synchronize file contents operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_fsync_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Synchronize file contents
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param datasync Flag indicating if only data should be flushed.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_fsync(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle, bool datasync,
		     spdk_fsdev_fsync_cpl_cb cb_fn, void *cb_arg);

/**
 * Flush operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_flush_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Flush
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_flush(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		     spdk_fsdev_flush_cpl_cb cb_fn,
		     void *cb_arg);

/**
 * Open a directory operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 *  Following parameters should be ignored if status != 0.
 * \param fhandle File handle
 */
typedef void (spdk_fsdev_opendir_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status,
		struct spdk_fsdev_file_handle *fhandle);

/**
 * Open a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param flags Operation flags.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_opendir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t unique, struct spdk_fsdev_file_object *fobject, uint32_t flags,
		       spdk_fsdev_opendir_cpl_cb cb_fn, void *cb_arg);

/**
 * Read directory per-entry callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param name Name of the entry
 * \param fobject File object. NULL for "." and "..".
 * \param attr File attributes.
 * \param offset Offset of the next entry
 *
 * \return 0 to continue the enumeration, an error code otherwice.
 */
typedef int (spdk_fsdev_readdir_entry_cb)(void *cb_arg, struct spdk_io_channel *ch,
		const char *name, struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
		off_t offset);

/**
 * Read directory operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_readdir_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Read directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle
 * \param offset Offset to continue reading the directory stream
 * \param entry_cb_fn Per-entry callback.
 * \param cpl_cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_readdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		       uint64_t offset,
		       spdk_fsdev_readdir_entry_cb entry_cb_fn, spdk_fsdev_readdir_cpl_cb cpl_cb_fn, void *cb_arg);

/**
 * Open a directory operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_releasedir_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
		int status);

/**
 * Open a directory
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_releasedir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			  uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
			  spdk_fsdev_releasedir_cpl_cb cb_fn, void *cb_arg);

/**
 * Synchronize directory contents operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_fsyncdir_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Synchronize directory contents
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object.
 * \param fhandle File handle
 * \param datasync Flag indicating if only data should be flushed.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_fsyncdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
			bool datasync,
			spdk_fsdev_fsyncdir_cpl_cb cb_fn, void *cb_arg);

/**
 * Acquire, modify or release a BSD file lock operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_flock_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Acquire, modify or release a BSD file lock
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object..
 * \param fhandle File handle.
 * \param operation Lock operation (see man flock and spdk_fsdev_file_lock_op).
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_flock(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		     enum spdk_fsdev_file_lock_op operation, spdk_fsdev_flock_cpl_cb cb_fn, void *cb_arg);

/**
 * Allocate requested space operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_fallocate_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Allocate requested space.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject File object..
 * \param fhandle File handle.
 * \param mode determines the operation to be performed on the given range, see fallocate(2)
 * \param offset starting point for allocated region.
 * \param length size of allocated region.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_fallocate(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			 uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
			 int mode, off_t offset, off_t length,
			 spdk_fsdev_fallocate_cpl_cb cb_fn, void *cb_arg);

/**
 * Copy a range of data from one file to another operation completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 * \param data_size Number of bytes written.
 */
typedef void (spdk_fsdev_copy_file_range_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch,
		int status, uint32_t data_size);

/**
 * Copy a range of data from one file to another.
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique Unique I/O id.
 * \param fobject_in IN File object.
 * \param fhandle_in IN File handle.
 * \param off_in Starting point from were the data should be read.
 * \param fobject_out OUT File object.
 * \param fhandle_out OUT File handle.
 * \param off_out Starting point from were the data should be written.
 * \param len Maximum size of the data to copy.
 * \param flags Operation flags, see the copy_file_range()
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_copy_file_range(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			       uint64_t unique,
			       struct spdk_fsdev_file_object *fobject_in, struct spdk_fsdev_file_handle *fhandle_in, off_t off_in,
			       struct spdk_fsdev_file_object *fobject_out, struct spdk_fsdev_file_handle *fhandle_out,
			       off_t off_out, size_t len, uint32_t flags,
			       spdk_fsdev_copy_file_range_cpl_cb cb_fn, void *cb_arg);


/**
 * I/O operation abortion completion callback
 *
 * \param cb_arg Context passed to the corresponding spdk_fsdev_ API
 * \param ch I/O channel.
 * \param status operation result. 0 if the operation succeeded, an error code otherwice.
 */
typedef void (spdk_fsdev_abort_cpl_cb)(void *cb_arg, struct spdk_io_channel *ch, int status);

/**
 * Abort an I/O
 *
 * \param desc Filesystem device descriptor.
 * \param ch I/O channel.
 * \param unique_to_abort Unique I/O id of the IO to abort.
 * \param cb_fn Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - operation cannot be initiated due to a lack of the internal IO objects
 */
int spdk_fsdev_abort(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		     uint64_t unique_to_abort, spdk_fsdev_abort_cpl_cb cb_fn, void *cb_arg);

#ifdef __cplusplus
}
#endif

#endif /* SPDK_FSDEV_H */
