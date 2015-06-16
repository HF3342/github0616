/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.zecloud.cn>
   This file is part of ZeFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef __METADATA_H__
#define __METADATA_H__

#include "xlator.h"
#include "call-stub.h"
#include "defaults.h"
#include "byte-order.h"
#include "common-utils.h"
#include "metadata-mem-types.h"
#include <fnmatch.h>  //Add by hf@20140606 for fnmatch
//#include "syncop.h"    /* Add by hf@20150324 */
//#include "metadata-helper.h"    /* Add by hf@20150324 */


typedef struct _fsedge {
	struct _fsnode *child,*parent;
	//struct _fsedge *nextchild,*nextparent;
	//struct _fsedge **prevchild,**prevparent;

	uint16_t nleng;
	char *name;
/* Add by hf@20150414 for posix */
	uint64_t               d_ino;
	uint64_t               d_off;
	uint32_t               d_len;
	uint32_t               d_type;
	uint32_t               d_sync;
	uint32_t               d_fd;   /*保存虚拟的fd */
	char                  *linkname;  /*保存符号链接path */
	struct list_head       fseg_list;   //add by hf@20150409 
	struct list_head       child_list;   // for  同一目录下所有fsedge实际链接关系
	struct list_head       parent_list;  // for hard link
/* End add */
} fsedge;


typedef struct _xattr {
	char *key;
	char *value;
	uint32_t vallen;
	struct list_head  attr_list;
} xattr;
typedef struct _fsnode {
#if 1
	struct stat stat;					// /usr/include/bits/stat.h
#else 
	uint32_t id;
	uint32_t ctime,mtime,atime;
	uint8_t type;
	uint8_t goal;
	uint16_t mode;	// only 12 lowest bits are used for mode, in unix standard upper 4 are used for object type, but since there is field "type" this bits can be used as extra flags
	uint32_t uid;
	uint32_t gid;
	//uint32_t trashtime;
	union _data {
		struct _ddata {				// type==TYPE_DIRECTORY
			fsedge *children;
			uint32_t nlink;
			uint32_t elements;
		} ddata;
		struct _sdata {				// type==TYPE_SYMLINK
			uint32_t pleng;
			uint8_t *path;
		} sdata;
		struct _devdata {
			uint32_t rdev;				// type==TYPE_BLOCKDEV ; type==TYPE_CHARDEV
		} devdata;
		struct _fdata {				// type==TYPE_FILE ; type==TYPE_TRASH ; type==TYPE_RESERVED
			uint64_t length;
			//uint64_t *chunktab;
			//uint32_t chunks;
		} fdata;
	} data;
#endif	
	uuid_t	               gfid;
	struct list_head       xattr_head;
	uint8_t                xattr_cnt;
	
	struct list_head       children;    // fsedge head_list
	struct list_head       parents;	    // for hard link 
	struct list_head       fsnd_list;   // add by hf@20150409 
	gf_lock_t              lock;        // add by hf@20150601 for fsnode (read || update)
} fsnode;

#define NODEHASHBITS (16)
#define NODEHASHSIZE (1<<NODEHASHBITS)
//#define NODEHASHPOS(nodeid) ((nodeid)&(NODEHASHSIZE-1))
#define NODEHASHPOS(uuid) ((uuid[15] + (uuid[14] << 8))&(NODEHASHSIZE-1))

struct metadata_node_table {
		gf_lock_t       lock;
		struct  list_head *fsnodes_list;
		struct  list_head *fsedges_list;
		uint32_t        hashsize;                 //虚拟fd
		uint32_t        virfd_num;                 //虚拟fd
		//fsnode *fsnd_hashtable[NODEHASHSIZE];
		//fsedge *fseg_hashtable[NODEHASHSIZE];
		uint32_t		nodes;						// total number of _fsnode
		uint32_t		dirnodes;
		uint32_t		filenodes;
		uint64_t		total_metadata_mem;	// (Bytes)
} ;
typedef struct metadata_node_table metadata_node_table_t;

/* Add by hf@20150323 */

enum mt_defrag_type {
        GF_DEFRAG_CMD_START = 1,
        GF_DEFRAG_CMD_STOP = 1 + 1,
        GF_DEFRAG_CMD_STATUS = 1 + 2,
        GF_DEFRAG_CMD_START_LAYOUT_FIX = 1 + 3,
        GF_DEFRAG_CMD_START_FORCE = 1 + 4,
};
typedef enum mt_defrag_type mt_defrag_type;

enum mt_defrag_status_t {                          
    GF_DEFRAG_STATUS_NOT_STARTED = 0,              
    GF_DEFRAG_STATUS_STARTED = 1,                  
    GF_DEFRAG_STATUS_STOPPED = 2,                  
    GF_DEFRAG_STATUS_COMPLETE = 3,                 
    GF_DEFRAG_STATUS_FAILED = 4,                   
};                                                 
typedef enum mt_defrag_status_t mt_defrag_status_t;

struct mt_defrag_info_ { 
        uint64_t                     total_files;
        uint64_t                     total_data;
        uint64_t                     num_files_lookedup;
        uint64_t                     total_failures;
        //uint64_t                     skipped;
        gf_lock_t                    lock;
        int                          cmd;
        //pthread_t                    th;
        mt_defrag_status_t           defrag_status;
        //struct rpc_clnt             *rpc;
        //uint32_t                     connected;
        //uint32_t                     is_exiting;
        //uuid_t                       node_uuid;
        pid_t                        pid;
        inode_t                     *root_inode;
        struct timeval               start_time;
        gf_boolean_t                 stats;
};                                                      

typedef struct mt_defrag_info_ mt_defrag_info_t;
/* End add */


struct metadata_private {
	
        //gf_lock_t       lock;
        pthread_mutex_t mutex;
		pthread_t load_metadata_thread;
		metadata_node_table_t *table;
		
		int8_t	load_metadata_complete;			// 1:means loading metadata task has completed
		uint64_t	total_metadata_mem_limit;	// (Bytes)the threshold of memory for all metadata, if over this value, set keep_metadata_partially
		int8_t keep_metadata_partially;		// 1:means not all the metadata is kept in memory , if we can't lookup an node then lookup it in disk	
		mt_defrag_info_t      *defrag;
} ;
typedef struct metadata_private metadata_private_t;

/* Add by hf@20150424 for xattr */
typedef struct {
        xlator_t    *this;
        dict_t      *xattr;
        struct iatt *stbuf;
        loc_t       *loc;
        inode_t     *inode; /* for all do_xattrop() key handling */
        fsnode      *fsnd;
		int          fd;
        int          flags;
} metadata_xattr_filler_t;

struct mtdata_fd {
	int     fd;      /* fd returned by the kernel */
	int32_t flags;   /* flags for open/creat      */
	DIR    *dir;     /* handle returned by the kernel */
    int     odirect;
	fsnode *fsnd;    /*add by hf@0602 for fd&fsnode */
	fsedge *fseg;    /*add by hf@0602 for fd&fsedge */
    struct list_head list; /* to add to the janitor list */
};
/* End add */

/* Add by hf@20150506 for write operation */
struct metadata_local {
        loc_t   loc;
        loc_t   loc2;
        fd_t   *fd;
        char   *linkname;
        char   *key;
        dict_t *xattr;
		int16_t optype;
};
unsigned int BKDRHash(char *str);
#define EDGEHASHPOS(name, uuid) ((BKDRHash(name) + uuid[15] + (uuid[14] << 8))&(NODEHASHSIZE-1)) // For fsedge hash 
/* End add */

inline fsnode *fsnode_new ();

inline void fsnode_destroy (fsnode *p);

inline fsedge *fsedge_new ();

inline void fsedge_destroy (fsedge *p);

/* Add by hf Begin*/
void add_fsnode_to_hash_table(uuid_t gfid, fsnode *p,fsedge *eg, metadata_node_table_t *table);

void remove_fsnode_from_hash_table(fsnode *p, metadata_node_table_t *table);

fsnode *fsnodes_hdlk_node_find(gf_dirent_t  *entry, fsedge *pfseg, metadata_node_table_t *table, int *flag);

metadata_node_table_t *metadata_node_table_new();
fsnode *fsnodes_rootnode_create(loc_t *loc, struct iatt *iatt, dict_t *dict );
fsnode *fsnodes_node_create(dict_t *dict , gf_dirent_t  *entry , fsedge *fseg, fsnode *fsnd);

//fsedge *fsedges_edge_create(loc_t *loc, gf_dirent_t  *entry, fsedge *fseg, fsnode *per_fsnd, fsnode *nxt_fsnd);
fsedge *fsedges_edge_create(gf_dirent_t  *entry,  fsnode *per_fsnd, fsnode *nxt_fsnd, const char *lkname, int hdflag);

//void showfsnode(metadata_private_t  *priv);

//void showLfsedge(metadata_private_t  *priv);
//void showRfsedge(metadata_private_t  *priv);
void showFsnodes(metadata_private_t  *priv);
void showFsedges(metadata_private_t  *priv);

int metadata_fd_ctx_get (fd_t *fd, xlator_t *this, struct mtdata_fd **pfd);
dict_t * metadata_lookup_xattr_get (xlator_t *this, loc_t *loc, dict_t *xattr_req, struct iatt *buf, fsnode* fsnd);

fsedge *get_next_fsedge(metadata_node_table_t * table, uuid_t  gfid, const char *name );
fsnode *get_next_fsnode(metadata_node_table_t * table, uuid_t  gfid);

fsedge *fsedges_edge_add(struct dirent  *entry, fsnode *per_fsnd, fsnode *nxt_fsnd, const char *lkname);
fsnode *fsnodes_node_add(dict_t *dict , struct iatt  *d_stat);

void fsnodes_node_del(metadata_node_table_t *table, uuid_t  gfid, ia_type_t ia_type);
void fsnodes_edge_del(metadata_node_table_t *table, uuid_t  gfid, const char *name);
void fsnodes_node_upd(fsnode *fsnd , struct iatt  *d_stat, int hdflag);

fsnode *metadata_get_fsnode(metadata_node_table_t *table, loc_t *loc);

void fsnode_node_edge_destory(fsnode *fsnd);
int fsnode_xattr_del_forupd(char *key, fsnode *fsnd);
uint32_t fsnode_xattr_upd (xlator_t *this, loc_t *loc, dict_t *xattr_req, fsnode* fsnd);

gf_boolean_t metadata_special_xattr (char **pattern, char *key);
int32_t fsnode_xattr_from_key_get_value(fsnode *fsnd, const char *name, void *value, size_t size);

int32_t fsnode_xattr_get_value(xlator_t *this, dict_t *dict , char *key, fsnode *fsnd);
//add by hf 2015-06-01-->
int32_t metadata_releasedir (xlator_t *this, fd_t *fd);
int32_t metadata_release (xlator_t *this, fd_t *fd);
////add by hf,2015-06-01<--

int32_t fsnode_list_all_xattr(xlator_t *this, fsnode *fsnd, dict_t *dict);

int32_t fsnode_setxattr(fsnode *fsnd, const char *name, void *value, size_t size, int flags);

void fsnodes_node_destory(metadata_node_table_t *table, fsnode *fsnd, ia_type_t ia_type);
void fsnodes_edge_destory(fsedge *fseg, const char *name);
#endif
