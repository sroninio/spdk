#ifndef NVROCKS_RPCLIB_MAIN_H
#define NVROCKS_RPCLIB_MAIN_H
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>		// For attributes queries
#include <sys/statvfs.h>

#ifdef __cplusplus
extern "C" {
#endif
	// Small subset of NFS v4.2 spec, just for API. Avoid including the full spec
	struct nvr_fh {
		unsigned int len;
		char* val;
	};

	struct nvr_stateid4 {
		uint32_t seqid;
		char opaque[12];
	};

	struct nvrocks_rpc_client;
	struct nvrocks_rpc_client* nvr_rpc_client_create(const char* domain, const char* mds_addr, uint16_t mds_port, uint8_t n_cpus);
	void           nvr_rpc_client_destroy(		struct nvrocks_rpc_client*);
	const struct nvr_fh*
	               nvr_rpc_client_get_root_fh(	struct nvrocks_rpc_client*);
	bool           nvr_rpc_client_is_connected(	struct nvrocks_rpc_client*);
	int            nvr_rpc_client_lookup(		struct nvrocks_rpc_client*, struct nvr_fh* parent_fh, const char* name, struct nvr_fh* out_fh, struct stat* retattr);
	int            nvr_rpc_client_open(			struct nvrocks_rpc_client*, struct nvr_fh* parent_fh, const char* filename, struct nvr_stateid4* out_stateid, struct nvr_fh* out_fh, bool force_create);
	int            nvr_rpc_client_open_file(	struct nvrocks_rpc_client*, struct nvr_fh* file_fh, struct nvr_stateid4* out_stateid);
	int            nvr_rpc_client_remove(		struct nvrocks_rpc_client*, struct nvr_fh* parent_fh, const char* filename);
	int            nvr_rpc_client_set_size(		struct nvrocks_rpc_client*, struct nvr_fh* file_fh, uint64_t  newsize);
	int            nvr_rpc_client_get_size(		struct nvrocks_rpc_client*, struct nvr_fh* file_fh, uint64_t* retsize);
	int            nvr_rpc_client_get_attr(		struct nvrocks_rpc_client*, struct nvr_fh* file_fh, struct stat* retattr);
	int            nvr_rpc_client_get_fsattr(	struct nvrocks_rpc_client*, struct nvr_fh* file_fh, struct statvfs* retattr);
	int            nvr_rpc_client_layoutget(	struct nvrocks_rpc_client*, struct nvr_fh* file_fh, struct nvr_stateid4* in_out_stid, bool can_write, uint64_t offset, uint32_t len);
	int            nvr_rpc_client_layoutret(	struct nvrocks_rpc_client*, struct nvr_fh* file_fh, struct nvr_stateid4* in_out_stid, bool can_write, uint64_t offset, uint32_t len);
	int            nvr_rpc_client_close_fh(		struct nvrocks_rpc_client*, struct nvr_fh* file_fh, const struct nvr_stateid4* stateid, uint64_t* newsize);
	int            nvr_rpc_client_mkdir(		struct nvrocks_rpc_client*, struct nvr_fh* parent_fh, const char* dirname);
	int            nvr_rpc_client_readdir(      struct nvrocks_rpc_client*, struct nvr_fh* file_fh, char* dirlist, uint32_t len);
#ifdef __cplusplus
}
#endif

#endif // NVROCKS_RPCLIB_MAIN_H
