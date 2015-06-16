/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.zecloud.cn>
   This file is part of ZeFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

//#if METADATA

#include "metadata.h"
#include "options.h"
#include "zefs3-xdr.h"
#include "syscall.h"
#include "syncop.h"
// cbk function

/* Add by hf@20150414 for metadata */
struct metadata_local;
typedef struct metadata_local metadata_local_t;

uint64_t
metadata_fill_ino_from_gfid (struct iatt *buf)
{
        uint64_t temp_ino = 0;
        int j = 0;
        int i = 0;

        /* consider least significant 8 bytes of value out of gfid */
        if (uuid_is_null (buf->ia_gfid)) {
                buf->ia_ino = -1;
                goto out;
        }
        for (i = 15; i > (15 - 8); i--) {
		temp_ino += (uint64_t)(buf->ia_gfid[i]) << j;
                j += 8;
        }
out:
		return temp_ino;
}
metadata_local_t *
metadata_local_get (call_frame_t *frame)
{
        metadata_local_t *local = NULL;

        local = frame->local;
        if (local)
                goto out;

        local = GF_CALLOC (sizeof (*local), 1, gf_metadata_mt_private_t);
        if (!local)
                goto out;

        frame->local = local;
out:
        return local;
}

/* metadata set virturl fd return directly 有待优化*/
uint32_t
metadata_fd_virt_set (xlator_t *this,  metadata_node_table_t *table, fsnode *fsnd, fd_t *fd)
{
        uint32_t         ret = -1;
		fsedge *fseg     = NULL;
		struct mtdata_fd *pfd       = NULL;

		if(__is_root_gfid (fsnd->gfid))
			goto set;

		if(fd){
			fseg = list_entry(fsnd->parents.next, struct _fsedge, parent_list);  //20150530 have bug ?
//gf_log ("", GF_LOG_INFO, "1-find_next_fsdnode src_name=[%s], look_name=[%s] is the  same  ", 
//							loc->name, fseg->name);
	        LOCK(&table->lock);
   			{
				table->virfd_num ++;
	        }
	        UNLOCK(&table->lock);

			if(table->virfd_num == 65536) //达到预定大小值后，重置为0， 不太可能同时打开这么多目录
				table->virfd_num = 0;
			fseg->d_fd = table->virfd_num;
		}

set:
gf_log ("", GF_LOG_INFO, "metadata_fd_virt_set fd_value=[%d], fsnd->gfid=[%02x%02x]", table->virfd_num, fsnd->gfid[14], fsnd->gfid[15]);
		pfd = GF_CALLOC (1, sizeof (*pfd), gf_metadata_mt_fsnode_fd);
		if (!pfd) 
			goto out;

		pfd->fd = table->virfd_num;
		pfd->fsnd = fsnd;
		pfd->fseg = NULL;

        if(!list_empty(&fsnd->children)){
			fseg = list_entry(fsnd->children.next, struct _fsedge, child_list);
			pfd->fseg = fseg;
		}
		

		ret = fd_ctx_set (fd, this, (uint64_t)(long)pfd);
        if (ret){
 				gf_log (this->name, GF_LOG_WARNING,
                				"failed to set the fd context fd=%p", fd);
				goto out;
		}

        ret = 0;
out:
        if (ret == -1) {
            if (pfd) {
            		GF_FREE (pfd);
                    pfd = NULL;
			}
        }
        return ret;
}



static int gf_metadata_xattr_enotsup_log;
int
metadata_inode_xatt_get (metadata_node_table_t *table, loc_t *loc, 
							dict_t *dict, fsnode *fsnd, char *key)
{
    int                 ret         = 0;
	uint32_t            nodepos     = -1;
	char               *value       = NULL;
    ssize_t   	        xattr_size  = -1;	
	struct _xattr      *xattr         = NULL;
	struct _xattr      *tmp_xtr     = NULL;

	if (list_empty (&fsnd->xattr_head) )
   		goto out;

	nodepos = NODEHASHPOS(loc->gfid);
	if(key){
		list_for_each_entry_safe(xattr, tmp_xtr, &fsnd->xattr_head, attr_list){
			if(!strcmp(xattr->key, key)){
gf_log ("", GF_LOG_ERROR, "Test by hf@20150515 key=[%s], value=[%02x%02x]", key, xattr->value[2], xattr->value[3]);
				if(xattr && xattr->value){
					xattr_size = xattr->vallen;

                   	value = GF_CALLOC (1, xattr_size + 1,
                                    gf_metadata_mt_char);
                   	if (!value || xattr_size <= 0) {
                            gf_log ("", GF_LOG_WARNING,
                                   "getxattr failed. path=%s, key=%s",
                                    loc->path, key);
                            GF_FREE (value);
                    		goto out;;
                   	}

					memcpy(value, xattr->value, xattr_size);
                   	value[xattr_size] = '\0';

                  	ret = dict_set_bin (dict, key,
                                      value, xattr_size);
                   	if (ret < 0) {
                           gf_log ("", GF_LOG_DEBUG,
                                   "dict set failed. path: %s, key: %s",
                                    loc->path, key);
                            GF_FREE (value);
							goto out;
					}
				}
				break;
			}
		}
	}else{
//list all xattr
		list_for_each_entry_safe(xattr, tmp_xtr, &fsnd->xattr_head, attr_list){
				if(xattr){
					xattr_size = xattr->vallen;

                   	value = GF_CALLOC (1, xattr_size + 1,
                                    gf_metadata_mt_char);
                   	if (!value || xattr_size <= 0) {
                            gf_log ("", GF_LOG_WARNING,
                                   "getxattr failed. path=%s, key=%s",
                                    loc->path, key);
                            GF_FREE (value);
                    		goto out;;
                   	}

					memcpy(value, xattr->value, xattr_size);
                   	value[xattr_size] = '\0';

gf_log ("", GF_LOG_ERROR, "Test by hf@20150515 key=[%s], value=[%02x%02x]", xattr->key, xattr->value[2], xattr->value[3]);
					ret = dict_set_dynptr (dict, xattr->key, value, xattr_size);
               		if (ret < 0) {
                		gf_log ("", GF_LOG_ERROR, "dict set operation "
                    		"on %s for the key %s failed.", loc->path, xattr->key);
						GF_FREE (value);
                    	goto out;
					}
				}
		}
	}

out:
        return ret;
}

static struct mtdata_key {
    const char *name;
    int         load;
    int         check;
} mtdata_keys[] = {
    {
        .name = "system.posix_acl_access",
        .load = 0,
        .check = 1,
    },
    {
        .name = "system.posix_acl_default",
        .load = 0,
        .check = 1,
    },
    {
        .name = "security.selinux",
        .load = 0,
        .check = 1,
    },
    {
        .name = "security.capability",
        .load = 0,
        .check = 1,
    },
    {
        .name = "gfid-req",
        .load = 0,
        .check = 1,
    },
        {
                .name = NULL,
                .load = 0,
                .check = 0,
        }
};

void
metadata_load_reqs (xlator_t *this, dict_t *dict)
{
    const char *mtdata_key = NULL;
    int  i = 0;
    int  ret = 0;

    for (mtdata_key = mtdata_keys[i].name; (mtdata_key = mtdata_keys[i].name); i++) {
        if (!mtdata_keys[i].load)
            continue;
        ret = dict_set_int8 (dict, (char *)mtdata_key, 0);
        if (ret)
            return;
    }
}

static int
is_metadata_key_satisfied (const char *key)
{
	const char *mtdata_key = NULL;
	int  i = 0;

	if (!key)
		return 0;

	for (mtdata_key = mtdata_keys[i].name; (mtdata_key = mtdata_keys[i].name); i++) {
		if (!mtdata_keys[i].load)
			continue;
		if (strcmp (mtdata_key, key) == 0)
			return 1;
	}

	return 0;
}

struct checkpair {
    int  ret;
    dict_t *rsp;
};

static int
metadata_checkfn (dict_t *this, char *key, data_t *value, void *data)
{
        struct checkpair *pair = data;

		if (!is_metadata_key_satisfied (key))
			pair->ret = 0;

        return 0;
}
int
metadata_xattr_satisfied (xlator_t *this, dict_t *req, dict_t *rsp)
{
        struct checkpair pair = {
                .ret = 1,
                .rsp = rsp,
        };

        dict_foreach (req, metadata_checkfn, &pair);

        return pair.ret;
}

#if 0
struct stat *
get_next_fsnode_stat(fsedge * fseg, loc_t *loc,  struct stat * fsnd_stat, char *lkname)
{
		while(fseg) {
				if(!strcmp(loc->name, fseg->name)){
					fsnd_stat = &fseg->child->stat;
        			uuid_copy (loc->gfid, fseg->child->gfid);
					if(fseg->child->linkname){
						gf_log ("", GF_LOG_INFO, "This is link file fseg->name=[%s], linkname=[%s] ", fseg->name, fseg->child->linkname);
						strcpy(lkname, fseg->child->linkname);
					}
					gf_log ("", GF_LOG_INFO, "2-fseg parent fsdnode=[%02x%02x] name=[%s]", fseg->child->gfid[14], fseg->child->gfid[15], fseg->name);
					break;
					}
				fseg = fseg->nextparent;
		}
		return fsnd_stat;
}
#endif

int
metadata_parinode_iatt_get (metadata_node_table_t *table, loc_t *loc, struct iatt *iatt)
{
        int              ret = -1; 
		struct    stat   *stat = NULL;
		fsnode           *fsnd = NULL;
		fsedge           *fseg = NULL;

        if (uuid_is_null (loc->gfid) && uuid_is_null (loc->pargfid)) {
                gf_log ("", GF_LOG_ERROR,
                        "null gfid " );
                goto out;
        } 

        if (!uuid_is_null (loc->pargfid)) {
			fsnd = get_next_fsnode(table, loc->pargfid);
			if(!fsnd)
				goto out;
		}else{
			fsnd = get_next_fsnode(table, loc->gfid);
			if( !__is_root_gfid (loc->gfid)){
				fseg = list_entry(fsnd->parents.next, struct _fsedge, parent_list);
				if(fseg){
					fsnd = fseg->parent;
				}
			}
		}

		if(fsnd){
			stat = &fsnd->stat;
			if(!stat){
				gf_log (THIS->name, GF_LOG_INFO, "Not found this fsnode, gfid and pargfid is null ");
				goto out;
			}
   			uuid_copy (iatt->ia_gfid, fsnd->gfid);
		}

        LOCK (&table->lock);
        {
			iatt_from_stat(iatt, stat );
        }
        UNLOCK (&table->lock);

		ret = 0;
out:
		return ret;
}
int
metadata_inode_iatt_get (metadata_node_table_t *table , loc_t *loc, struct iatt *iatt)
{
        uint32_t         ret = -1;
		fsnode           *fsnd = NULL;

		fsnd  = metadata_get_fsnode(table, loc);
		if(!fsnd)
			goto out;

        iatt_from_stat(iatt, &fsnd->stat );
       	uuid_copy (iatt->ia_gfid, fsnd->gfid);

/*
        LOCK (&priv->table->lock);
        {
            iatt_from_stat(iatt, stat );
        }
        UNLOCK (&priv->table->lock);
*/
        //uuid_copy (iatt->ia_gfid, loc->gfid);
/*
        iatt->ia_ino    = gfid_to_ino (inode->gfid);
        iatt->ia_dev    = 42;
        iatt->ia_type   = inode->ia_type;
*/

		ret = 0;
out:
        return ret;
}

int
metadata_fsnode_stat_upd(metadata_node_table_t *table , uuid_t gfid, struct iatt *iatt )
{
        uint32_t         ret  = -1;
		fsnode          *fsnd = NULL;

        fsnd = get_next_fsnode(table, gfid);
        if(!fsnd){
            gf_log ("", GF_LOG_ERROR, "metadata_mknod_cbk uncached fali!");
            goto err;
        }

		LOCK(&fsnd->lock);
		{
			if (!iatt || !iatt->ia_ctime) {
            		fsnd->stat.st_atime = 0;
                    goto unlock;
            } 

        	iatt_to_stat(iatt,&fsnd->stat);
		}

unlock:
        UNLOCK(&fsnd->lock);

		ret = 0;
err:
		return ret;
}
void
metadata_local_wipe (xlator_t *this, metadata_local_t *local)
{
        if (!local)
                return;


        loc_wipe (&local->loc);

        loc_wipe (&local->loc2);

        if (local->fd)
                fd_unref (local->fd);

        GF_FREE (local->linkname);

        GF_FREE (local->key);

        if (local->xattr)
                dict_unref (local->xattr);


        GF_FREE (local);
        return;
}
#define MTDATA_STACK_UNWIND(fop, frame, params ...) do {           \
                metadata_local_t  *__local = NULL;                    \
                xlator_t    *__xl    = NULL;                    \
                if (frame) {                                    \
                        __xl         = frame->this;             \
                        __local      = frame->local;            \
                        frame->local = NULL;                    \
                }                                               \
                STACK_UNWIND_STRICT (fop, frame, params);       \
                metadata_local_wipe (__xl, __local);                 \
        } while (0)

/* End add */

#define CALL_STATE(frame)   ((server_state_t *)frame->root->state)

int32_t
metadata_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, inode_t *inode,
                    struct iatt *buf, dict_t *xdata, struct iatt *postparent)
{
gf_log ("", GF_LOG_ERROR, "metadata_lookup_cbk buf->gfid=[%02x%02x], postparent->gfid=[%02x%02x] ", 
			buf->ia_gfid[14],buf->ia_gfid[15], postparent->ia_gfid[14],postparent->ia_gfid[15]);

        metadata_local_t       *local     = NULL;
		inode_t                 *link_inode = NULL;   //20150609 for inode

        local = frame->local;
        if (!local)
            goto uncached;

//set entry->name inode_table name_hash 
	if(inode){
        if (!__is_root_gfid (inode->gfid)) {

//gf_log (this->name, GF_LOG_INFO, "4444444444444444444444444444name=[%s] [%ld]", local->loc.name, (unsigned long)local->loc.parent);
                link_inode = inode_link (inode, local->loc.parent,
                                         local->loc.name, buf);
                if (link_inode) {
                        inode_lookup (link_inode);
                        inode_unref (link_inode);
                }
        }
	}
/* End add */

#if 0
		local = frame->local;
        if (!local)
                goto out;

        if (op_ret != 0)
                goto out;
/*
        if (local->loc.parent) {
                metadata_inode_iatt_set (this, local->loc.parent, postparent);
        }

        if (local->loc.inode) {
                metatdata_inode_iatt_set (this, local->loc.inode, stbuf);
                metatdata_inode_xatt_set (this, local->loc.inode, xdata);
        }
*/
out:
/*
        MDC_STACK_UNWIND (lookup, frame, op_ret, op_errno, inode, stbuf,
                          dict, postparent);
*/
#endif
		//加载完成
/*

		MTDATA_STACK_UNWIND(lookup, frame, op_ret, op_errno, inode, buf,
                         xdata, postparent);
*/

uncached:
        MTDATA_STACK_UNWIND (lookup, frame, op_ret, op_errno, inode, buf,
                             xdata, postparent);
		return 0;
}

int32_t
metadata_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iatt *buf,
                  dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_stat_cbk  op_ret=[%d]", op_ret);

        STACK_UNWIND_STRICT (stat, frame, op_ret, op_errno, buf, xdata);
        return 0;
}


int32_t
metadata_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                      struct iatt *postbuf,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_truncate_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(op_ret < 0)
            goto uncached;

        local = frame->local;
        if (!local)
            goto uncached;

		op_ret = metadata_fsnode_stat_upd(priv->table , local->loc.gfid, postbuf);
// loss set max size err ?????
		if(local->xattr){
			op_ret = fsnode_xattr_upd(this, &local->loc, local->xattr, fsnd);
			gf_log (this->name, GF_LOG_ERROR, "metadata_truncate_cbk op_ret=[%d], op_errno=[%d]", op_ret ,op_errno); 
		}
		if (op_ret < 0)
			op_errno = -op_ret;

uncached:

        MTDATA_STACK_UNWIND (truncate, frame, op_ret, op_errno, prebuf,
                             postbuf, xdata);
        return 0;
}

int32_t
metadata_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                       int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                       struct iatt *postbuf,
                       dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_ftruncate_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
        struct mtdata_fd       *pfd       = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;

        if (!local)
            goto uncached;

		if(op_ret < 0)
            goto uncached;

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;

		LOCK(&fsnd->lock);
		{
			iatt_to_stat(postbuf,&fsnd->stat);
		}
		UNLOCK(&fsnd->lock);
// loss set max size err ?????
		if(local->xattr){
			op_ret = fsnode_xattr_upd(this, &local->loc, local->xattr, fsnd);
			gf_log (this->name, GF_LOG_ERROR, "metadata_ftruncate_cbk op_ret=[%d], op_errno=[%d]", op_ret ,op_errno); 
		}
		if (op_ret < 0)
			op_errno = -op_ret;

uncached:

        MTDATA_STACK_UNWIND (ftruncate, frame, op_ret, op_errno, prebuf,
                             postbuf, xdata);
        return 0;
}

int32_t
metadata_access_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno,
                    dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_access_cbk ");

        STACK_UNWIND_STRICT (access, frame, op_ret, op_errno, xdata);
        return 0;
}

int32_t
metadata_readlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, const char *path,
                      struct iatt *buf, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_readlink_cbk path=[%s]",path);

        STACK_UNWIND_STRICT (readlink, frame, op_ret, op_errno, path, buf,
                             xdata);
        return 0;
}


int32_t
metadata_mknod_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, inode_t *inode,
                   struct iatt *buf, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_mkmod_cbk  op_ret=[%d]", op_ret);

		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);

        if (op_ret != 0)
                goto uncached;

        local = frame->local;
        if (!local)
                goto uncached;

		priv = this->private;

		if(local->loc.parent){
			op_ret = metadata_fsnode_stat_upd(priv->table, preparent->ia_gfid, postparent);
		}

		if(local->loc.inode){
			op_ret = metadata_fsnode_stat_upd(priv->table, local->loc.gfid, buf);
			if(local->xattr){
				op_ret = fsnode_xattr_upd(this, &local->loc, local->xattr, fsnd);
				gf_log (this->name, GF_LOG_ERROR, "metadata_setxattr_cbk op_ret=[%d], op_errno=[%d]", op_ret ,op_errno); 
			}
		}

uncached:

        MTDATA_STACK_UNWIND (mknod, frame, op_ret, op_errno, inode,
                             buf, preparent, postparent, xdata);
        return 0;
}

int32_t
metadata_mkdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, inode_t *inode,
                   struct iatt *buf, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_mkdir_cbk buf->gfid=[%02x%02x], preparent->gfid=[%02x%02x]", 
				buf->ia_gfid[14], buf->ia_gfid[15],
				preparent->ia_gfid[14], preparent->ia_gfid[15]);

		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
		fsnode                 *newfsnode = NULL;
		fsedge                 *newfsedge = NULL;
        metadata_local_t       *local     = NULL;
		struct dirent          *entry     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);

        local = frame->local;

        if (op_ret != 0)
                goto uncached;

        if (!local)
                goto uncached;

		priv = this->private;

		fsnd = get_next_fsnode(priv->table, preparent->ia_gfid);
		if(!fsnd){
			gf_log (this->name, GF_LOG_ERROR, "metadata_symlink_cbk uncached fali!");
			goto uncached;
		}
		//fseg = get_next_fsedge(priv->table, preparent->ia_gfid, local->loc.name);

        entry = GF_CALLOC (1, sizeof(struct dirent), 
                               gf_common_mt_gf_dirent_t);
		if(!entry)
			goto uncached;

		entry->d_ino = metadata_fill_ino_from_gfid(buf);
		entry->d_off = entry->d_ino;   //文件偏移量off在metadata层，暂时无用，只要不是空，就可以遍历成功。
		entry->d_reclen = strlen(local->loc.name);
		entry->d_type = buf->ia_type;
		strcpy(entry->d_name , local->loc.name);

/*
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_off=[%ld]", entry->d_off);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_ino=[%ld]", entry->d_ino);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_type=[%d]", entry->d_type);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_reclen=[%d]", entry->d_reclen);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_name =[%s]", entry->d_name);
*/
		
		newfsnode = fsnodes_node_add(local->xattr, buf);
		newfsedge = fsedges_edge_add(entry,  fsnd, newfsnode, NULL);

		if(newfsedge){
			gf_log (this->name, GF_LOG_INFO, "Last fseg parent fsdnode=[%02x%02x] name=[%s]",
					newfsedge->child->gfid[14], newfsedge->child->gfid[15], newfsedge->name);
		}else{
			//元数据缓存失败 怎么处理?  磁盘写入成功
			gf_log (this->name, GF_LOG_INFO, "metadata_mkdir_cbk uncached fali!");
			op_ret = -1;
			goto uncached;
		}

		add_fsnode_to_hash_table(preparent->ia_gfid, newfsnode, newfsedge, priv->table);
		//update stat of parent fsnode 
		metadata_fsnode_stat_upd(priv->table , local->loc.pargfid, postparent);

uncached:
		if(entry){
			GF_FREE(entry);
			entry = NULL;
		}

        MTDATA_STACK_UNWIND(mkdir, frame, op_ret, op_errno, inode,
                             buf, preparent, postparent, xdata);
        return 0;
}

int32_t
metadata_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct iatt *preparent,
                    struct iatt *postparent, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_unlink_cbk  op_ret=[%d], preparent->gfid=[%02x%02x], linknumber=[%d]",
                op_ret, preparent->ia_gfid[14], preparent->ia_gfid[15], preparent->ia_nlink);

        metadata_private_t     *priv      = NULL;
        fsedge                 *fseg      = NULL;
        fsnode                 *parfsnd   = NULL;
        metadata_local_t       *local     = NULL;
		int32_t                 d_type    = 0;
		struct iatt             stbuf     = {0, };

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);

        local = frame->local;
        if (op_ret != 0)
                goto uncached;

        if (!local)
                goto uncached;

        priv = this->private;

/*
		parfsnd = get_next_fsnode(priv->table, preparent->ia_gfid);
		if(!parfsnd)
			goto uncached;
*/

        fseg = get_next_fsedge(priv->table, preparent->ia_gfid, local->loc.name);
        if(!fseg){
            gf_log (this->name, GF_LOG_INFO, "metadata_unlink_cbk not find this fsedge name=[%s]",
                local->loc.name);
            goto uncached;
        }
		parfsnd = fseg->parent;
		
		//for hard link 当删除一个硬链接时，需要更新其他硬链接对应的stat
		d_type = ia_type_from_st_mode (fseg->child->stat.st_mode);

	    iatt_from_stat (&stbuf, &fseg->child->stat);
		
/*
        gf_log (this->name, GF_LOG_INFO, "metadata_unlink_cbk hard link file linknumber =[%ld],d_type=[%d]",
				fseg->child->stat.st_nlink , d_type);
*/


		if (IA_ISREG (d_type) && fseg->child->stat.st_nlink >1){
			stbuf.ia_nlink--;
			fsnodes_node_upd(fseg->child, &stbuf, 1); 
			if(1 == fseg->child->stat.st_nlink){ //硬链接文件数剩最后一个，再删除则需要删除fsnode+fsedge
        		fsnodes_node_del(priv->table, fseg->child->gfid, local->loc.inode->ia_type);
        		fsnodes_edge_del(priv->table, preparent->ia_gfid, local->loc.name);
			}
        	fsnodes_edge_del(priv->table, preparent->ia_gfid, local->loc.name);
		}else{
/*
        	fsnodes_node_del(priv->table, fseg->child->gfid, local->loc.inode->ia_type);
        	fsnodes_edge_del(priv->table, preparent->ia_gfid, local->loc.name);
*/
			fsnodes_node_destory(priv->table, fseg->child, local->loc.inode->ia_type);
			fsnodes_edge_destory(fseg, local->loc.name);
		}
		//更新父目录的状态信息 有待优化？  ctime更新有问题。
		if(!uuid_is_null (parfsnd->gfid))
			fsnodes_node_upd(parfsnd, postparent, 0); 

uncached:

        MTDATA_STACK_UNWIND (unlink, frame, op_ret, op_errno, preparent,
                             postparent, xdata);
        return 0;
}

int32_t
metadata_rmdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *preparent,
                   struct iatt *postparent,
                   dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_rmdir_cbk  op_ret=[%d], preparent->gfid=[%02x%02x]",
                op_ret, preparent->ia_gfid[14], preparent->ia_gfid[15]);

        metadata_private_t     *priv      = NULL;
        fsedge                 *fseg      = NULL;
        metadata_local_t       *local     = NULL;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);

        if (op_ret != 0)
                goto uncached;

        local = frame->local;
        if (!local)
                goto uncached;

        priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        fseg = get_next_fsedge(priv->table, preparent->ia_gfid, local->loc.name);
        if(!fseg){
            gf_log (this->name, GF_LOG_DEBUG, "metadata_unlink_cbk not find this fsedge name=[%s]",
                local->loc.name);
            goto uncached;
        }
//缺少父目录stat的更新
		if(!uuid_is_null (fseg->parent->gfid))
			fsnodes_node_upd(fseg->parent, postparent, 0); 

/*
        fsnodes_node_del(priv->table, fseg->child->gfid, local->loc.inode->ia_type);
        fsnodes_edge_del(priv->table, preparent->ia_gfid, local->loc.name);
*/
		fsnodes_node_destory(priv->table, fseg->child, local->loc.inode->ia_type);
		fsnodes_edge_destory(fseg, local->loc.name);

uncached:
        MTDATA_STACK_UNWIND (rmdir, frame, op_ret, op_errno, preparent,
                             postparent, xdata);
        return 0;
}


int32_t
metadata_symlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, inode_t *inode,
                     struct iatt *buf, struct iatt *preparent,
                     struct iatt *postparent, dict_t *xdata)
{
// 需要更新缓存中对应扩展属性，在xdata中。
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_symlink_cbk buf->gfid=[%02x%02x%02x%02x], preparent->gfid=[%02x%02x%02x%02x]", 
				buf->ia_gfid[12], buf->ia_gfid[13],buf->ia_gfid[14], buf->ia_gfid[15],
				preparent->ia_gfid[12], preparent->ia_gfid[13],preparent->ia_gfid[14], preparent->ia_gfid[15]);

		metadata_private_t     *priv      = NULL;
		fsnode                 *parfsnd   = NULL;
		//fsedge                 *fseg      = NULL;
		fsnode                 *newfsnode = NULL;
		fsedge                 *newfsedge = NULL;
		int32_t                 posnode   = 0;
        metadata_local_t       *local     = NULL;
		struct dirent          *entry     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);

        if (op_ret != 0)
                goto uncached;

        local = frame->local;
        if (!local)
                goto uncached;

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		parfsnd = get_next_fsnode(priv->table, preparent->ia_gfid);
		if(!parfsnd){
			gf_log (this->name, GF_LOG_ERROR, "metadata_symlink_cbk uncached fali!");
			goto uncached;
		}
		//fseg = get_next_fsedge(priv->table, preparent->ia_gfid, local->loc.name);

        entry = GF_CALLOC (1, sizeof(*entry),
                               gf_common_mt_gf_dirent_t);
		if(!entry)
			goto uncached;

		entry->d_ino = metadata_fill_ino_from_gfid(buf);
		entry->d_off = entry->d_ino;   //文件偏移量off在metadata层，暂时无用，只要保证d_off唯一，就可以遍历成功。
		entry->d_reclen = strlen(local->loc.name);
		entry->d_type = buf->ia_type;
		strcpy(entry->d_name , local->loc.name);

		newfsnode = fsnodes_node_add(local->xattr, buf);
		newfsedge = fsedges_edge_add(entry, parfsnd, newfsnode, local->linkname);

		if(newfsedge){
			gf_log (this->name, GF_LOG_INFO, "Last fseg parent posnode=[%d],fsdnode=[%02x%02x] name=[%s]",
					posnode, newfsedge->child->gfid[14], newfsedge->child->gfid[15], newfsedge->name);
		}else{
			//元数据缓存失败 怎么处理?  磁盘写入成功
			gf_log (this->name, GF_LOG_ERROR, "metadata_symlink_cbk uncached fali!");
			goto uncached;
		}

		add_fsnode_to_hash_table(preparent->ia_gfid, newfsnode, newfsedge, priv->table);

uncached:
		if(entry){
			GF_FREE(entry);
			entry = NULL;
		}

        MTDATA_STACK_UNWIND (symlink, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}


int32_t
metadata_rename_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct iatt *buf,
                    struct iatt *preoldparent, struct iatt *postoldparent,
                    struct iatt *prenewparent, struct iatt *postnewparent,
                    dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_rename_cbk  op_ret=[%d]", op_ret);

		metadata_private_t     *priv         = NULL;
		fsnode                 *fsnd         = NULL;
		fsnode                 *newfsnd      = NULL;
		fsnode                 *oldparfsnd   = NULL;
		fsnode                 *newparfsnd   = NULL;
		fsedge                 *fseg         = NULL;
        metadata_local_t       *local        = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);

        if (op_ret != 0)
                goto uncached;

        local = frame->local;
        if (!local)
                goto uncached;

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		oldparfsnd = get_next_fsnode(priv->table, postoldparent->ia_gfid);
		if(!oldparfsnd){
			op_errno = ENOENT;
			gf_log (this->name, GF_LOG_ERROR, "metadata_rename_cbk uncached fali!");
			goto uncached;
		}

		newparfsnd = get_next_fsnode(priv->table, postnewparent->ia_gfid);
		if(!newparfsnd){
			op_errno = ENOENT;
			gf_log (this->name, GF_LOG_ERROR, "metadata_rename_cbk uncached fali!");
			goto uncached;
		}

		fsnd = metadata_get_fsnode(priv->table, &local->loc);
		if(!fsnd)
			goto uncached;

		if(!IA_ISDIR(buf->ia_type)){
			newfsnd = metadata_get_fsnode(priv->table, &local->loc2);
			if(newfsnd)
				//if target fsnode is not directory , then unlink the fsnode and fsedge 
				fsnode_node_edge_destory(newfsnd);
		}

		fseg = list_entry(fsnd->parents.next, struct _fsedge, parent_list);
		if(fseg){
			strcpy(fseg->name , local->loc2.name);
			fseg->nleng = strlen(local->loc2.name);
		}
		fsnodes_node_upd(oldparfsnd, postoldparent, 0);
		fsnodes_node_upd(newparfsnd, postnewparent, 0);
		fsnodes_node_upd(fsnd, buf, 0);

//fsnode->gfid not chanage，so fsnode in fsnode_list table position  invariant
		LOCK (&priv->table->lock); 
		{
			uint32_t   oldposnode = 0;                 
			uint32_t   newposnode = 0;                 
         	oldposnode = EDGEHASHPOS((char*)local->loc.name, local->loc.pargfid);
         	newposnode = EDGEHASHPOS((char*)local->loc2.name, local->loc2.pargfid);

			fseg->parent = newparfsnd;
			list_move(&fseg->fseg_list, &priv->table->fsedges_list[newposnode]);
			list_move(&fseg->child_list, &newparfsnd->children);
		}
		UNLOCK (&priv->table->lock); 

#if DEBUG
要重命名的fsnode对应的gfid不会改变，因此对应的fsnode_list table中的索引位置不变，
源文件是文件：  目标文件是文件: 删除目标文件，更新父目录的stat        
                目标文件时目录: 源文件移动到目标目录下， 更新stat
源文件是目录：  目标文件时文件: 覆盖失败，不允许这样做
                目标文件时目录：源文件移动到目标目录下， 更新stat
如果跨节点rename怎么处理？
#endif


uncached:
        MTDATA_STACK_UNWIND (rename, frame, op_ret, op_errno, buf, preoldparent,
                             postoldparent, prenewparent, postnewparent, xdata);
        return 0;
}


int32_t
metadata_link_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, inode_t *inode,
                  struct iatt *buf, struct iatt *preparent,
                  struct iatt *postparent,
                  dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_link_cbk  op_ret=[%d], linknumber=[%d]", op_ret, buf->ia_nlink);
gf_log (this->name, GF_LOG_INFO, "metadata_link_cbk buf->gfid=[%02x%02x%02x%02x], preparent->gfid=[%02x%02x%02x%02x]", 
				buf->ia_gfid[12], buf->ia_gfid[13],buf->ia_gfid[14], buf->ia_gfid[15],
				preparent->ia_gfid[12], preparent->ia_gfid[13],preparent->ia_gfid[14], preparent->ia_gfid[15]);

		metadata_private_t     *priv      = NULL;
		fsnode                 *srcfsnd   = NULL;
		fsedge                 *srcfseg   = NULL; 
		fsnode                 *parfsnode = NULL;
		//fsedge                 *parfsedge = NULL;
		fsedge                 *newfsedge = NULL;
		int32_t                 posnode   = 0;
        metadata_local_t       *local     = NULL;
		struct dirent          *entry     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);

        local = frame->local;

        if (op_ret != 0)
                goto uncached;

        if (!local)
                goto uncached;

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

/* 找到硬链接源文件 在缓存中的fsnode  硬链接时只需要hashtable中fsedge */
gf_log (this->name, GF_LOG_INFO, "metadata_link_cbk loc->path=[%s], loc->name[%s], loc->gfid=[%02x%02x]",
					local->loc.path, local->loc.name, local->loc.gfid[14], local->loc.gfid[15]);

		if(!uuid_is_null (preparent->ia_gfid)){
			parfsnode = get_next_fsnode(priv->table, preparent->ia_gfid);
			if(!parfsnode){
				gf_log (this->name, GF_LOG_INFO, "metadata_link_cbk uncached fali!");
				op_ret = -1;
				goto uncached;
			}
		}

		if(!uuid_is_null (local->loc.gfid)){
			srcfsnd = get_next_fsnode(priv->table, local->loc.gfid);
			if(srcfsnd){
				//srcfseg  = srcfsnd->parents; //20150529
			}else{
				gf_log (this->name, GF_LOG_INFO, "metadata_link_cbk uncached fali!");
				op_ret = -1;
				goto uncached;
			}
		}else{
			srcfseg = get_next_fsedge(priv->table, local->loc.pargfid, local->loc.name);
			if(srcfseg)
				srcfsnd = srcfseg->child;
		}
/* 查找硬链接文件所在新的目录对应的父目录的fsnode */
/*
gf_log (this->name, GF_LOG_INFO, "metadata_link_cbk loc2->path=[%s],loc2->name=[%s],loc2->gfid=[%02x%02x]",
					local->loc2.path, local->loc2.name, local->loc2.gfid[14], local->loc2.gfid[15]);
*/
        entry = GF_CALLOC (1, sizeof(*entry),
                               gf_common_mt_gf_dirent_t);
		if(!entry)
			goto uncached;

		entry->d_ino = metadata_fill_ino_from_gfid(buf);
		entry->d_off = entry->d_ino;   //文件偏移量off在metadata层，暂时无用，只要保证d_off唯一，就可以遍历成功。
		entry->d_reclen = strlen(local->loc2.name);
		entry->d_type = buf->ia_type;
		strcpy(entry->d_name , local->loc2.name);

		//硬链接文件对应源文件对应的所有连接文件都要更新的属性和状态 
		fsnodes_node_upd(srcfsnd , buf, 1);
		//更新父目录状态
		//fsnodes_node_upd(srcfseg->parent , preparent, 0); // 20150529
		metadata_fsnode_stat_upd(priv->table, preparent->ia_gfid, postparent);
/*
gf_log (this->name, GF_LOG_INFO, "metadata_link_cbk parfsnode->gfid=[%02x%02x],name=[%s] +++++  srcfsnd->gfid=[%02x%02x], name=[%s]",
					parfsnode->gfid[14],parfsnode->gfid[15],parfsnode->parents->name,
					 srcfsnd->gfid[14], srcfsnd->gfid[15], srcfsnd->parents->name);
*/
		newfsedge = fsedges_edge_add(entry, parfsnode, srcfsnd, local->loc.path);

		if(newfsedge){
			gf_log (this->name, GF_LOG_INFO, "Last fseg parent posnode=[%d],fsdnode=[%02x%02x] name=[%s]",
					posnode, newfsedge->child->gfid[14], newfsedge->child->gfid[15], newfsedge->name);
		}else{
			//元数据缓存失败 怎么处理?  磁盘写入成功
			gf_log (this->name, GF_LOG_INFO, "metadata_link_cbk uncached fali!");
			op_ret = -1;
			goto uncached;
		}

		add_fsnode_to_hash_table(preparent->ia_gfid, NULL, newfsedge, priv->table);

uncached:
		if(entry){
			GF_FREE(entry);
			entry = NULL;
		}

        MTDATA_STACK_UNWIND (link, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}

int32_t
metadata_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, fd_t *fd, inode_t *inode,
                    struct iatt *buf, struct iatt *preparent,
                    struct iatt *postparent,
                    dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_create_cbk buf->gfid=[%02x%02x%02x%02x], preparent->gfid=[%02x%02x%02x%02x]", 
				buf->ia_gfid[12], buf->ia_gfid[13],buf->ia_gfid[14], buf->ia_gfid[15],
				preparent->ia_gfid[12], preparent->ia_gfid[13],preparent->ia_gfid[14], preparent->ia_gfid[15]);

/*
if(xdata->members_list)
gf_log ("", GF_LOG_ERROR, "----------------key=[%s], value=[%02x%02x]", xdata->members_list->key, 
			xdata->members_list->value->data[2], xdata->members_list->value->data[3]);
*/
		metadata_private_t     *priv      = NULL;
		fsnode                 *parfsnd   = NULL;
		//fsedge                 *fseg      = NULL;
		fsnode                 *newfsnode = NULL;
		fsedge                 *newfsedge = NULL;
		int32_t                 posnode   = 0;
        metadata_local_t       *local     = NULL;
		struct dirent          *entry     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);
        VALIDATE_OR_GOTO (fd, uncached);

        if (op_ret != 0)
                goto uncached;

        local = frame->local;
        if (!local)
                goto uncached;

		priv = this->private;

		/* get parent fsnode */
		parfsnd = get_next_fsnode(priv->table, preparent->ia_gfid);
		if(!parfsnd){
			gf_log (this->name, GF_LOG_ERROR, "metadata_create_cbk uncached fali!");
			goto uncached;
		}
		//fseg = get_next_fsedge(priv->table, preparent->ia_gfid, local->loc.name);

        entry = GF_CALLOC (1, sizeof(*entry),
                               gf_common_mt_gf_dirent_t);
		if(!entry)
			goto uncached;

		entry->d_ino = metadata_fill_ino_from_gfid(buf);
		entry->d_off = entry->d_ino;   //文件偏移量off在metadata层，暂时无用，只要保证d_off唯一，就可以遍历成功。
		entry->d_reclen = strlen(local->loc.name);
		entry->d_type = buf->ia_type;
		strcpy(entry->d_name , local->loc.name);

/*
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_off=[%ld]", entry->d_off);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_ino=[%ld]", entry->d_ino);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_type=[%d]", entry->d_type);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_reclen=[%d]", entry->d_reclen);
gf_log ("", GF_LOG_INFO, "Readir this  entry->d_name =[%s]", entry->d_name);
*/
		
		newfsnode = fsnodes_node_add(xdata, buf);
		newfsedge = fsedges_edge_add(entry, parfsnd, newfsnode, NULL);

		if(newfsedge){
			gf_log (this->name, GF_LOG_INFO, "Last fseg parent posnode=[%d],fsdnode=[%02x%02x] name=[%s]",
					posnode, newfsedge->child->gfid[14], newfsedge->child->gfid[15], newfsedge->name);
		}else{
			//元数据缓存失败 怎么处理?  磁盘写入成功
			gf_log (this->name, GF_LOG_INFO, "metadata_create_cbk uncached falied!");
			op_ret = -1;
			goto uncached;
		}

		add_fsnode_to_hash_table(preparent->ia_gfid, newfsnode, newfsedge, priv->table);
		metadata_fsnode_stat_upd(priv->table , local->loc.pargfid, postparent);

uncached:
		if(entry){
			GF_FREE(entry);
			entry = NULL;
		}
        MTDATA_STACK_UNWIND(create, frame, op_ret, op_errno, fd, inode, buf,
                             preparent, postparent, xdata);
        return 0;
}

int32_t
metadata_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, fd_t *fd,
                  dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_open_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
        metadata_local_t       *local     = NULL;
		fsnode                 *fsnd      = NULL;
        struct mtdata_fd       *pfd       = NULL;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (this->private, uncached);
        VALIDATE_OR_GOTO (fd, uncached);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;
        if (!local)
                goto uncached;

		fsnd = metadata_get_fsnode(priv->table, &local->loc);
		if(!fsnd){
			gf_log (this->name, GF_LOG_WARNING, "metadata_open_cbk uncached fali!");
			goto uncached;
		}

        pfd = GF_CALLOC (1, sizeof (*pfd), gf_metadata_mt_fsnode_fd);
        if (!pfd) {
                op_errno = errno;
                goto uncached;
        }

        pfd->fsnd   = fsnd;

        op_ret = fd_ctx_set (fd, this, (uint64_t)(long)pfd);
        if (op_ret)
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set the fd context path=%s fd=%p",
                        local->loc.path, fd);
        op_ret = 0;

uncached:

        MTDATA_STACK_UNWIND (open, frame, op_ret, op_errno, fd, xdata);
        return 0;
}

int32_t
metadata_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iovec *vector,
                   int32_t count, struct iatt *stbuf, struct iobref *iobref,
                   dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_readv_cbk  op_ret=[%d], count=[%d]", op_ret, count);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
        struct mtdata_fd       *pfd       = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;

        if (!local)
            goto uncached;

		if(op_ret < 0)
            goto uncached;

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;

		LOCK(&fsnd->lock);
		{
			iatt_to_stat(stbuf,&fsnd->stat);
		}
		UNLOCK(&fsnd->lock);

uncached:

        MTDATA_STACK_UNWIND (readv, frame, op_ret, op_errno, vector, count,
                             stbuf, iobref, xdata);
        return 0;
}


int32_t
metadata_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                    struct iatt *postbuf,
                    dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_writev_cbk  op_ret=[%d]", op_ret );
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
        struct mtdata_fd       *pfd       = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;
        if (!local)
            goto uncached;

		if(op_ret < 0)
            goto uncached;

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;

#if DEBUG
有待调优，直接赋值可能存在问题， 参照md_cache层有对time的检查
#endif
		LOCK(&fsnd->lock);
		{
			iatt_to_stat(postbuf,&fsnd->stat);
		}
		UNLOCK(&fsnd->lock);
		
uncached:

        MTDATA_STACK_UNWIND (writev, frame, op_ret, op_errno, prebuf, postbuf, xdata);
        return 0;
}


int32_t
metadata_flush_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno,
                   dict_t *xdata)
{
        STACK_UNWIND_STRICT (flush, frame, op_ret, op_errno, xdata);
        return 0;
}



int32_t
metadata_fsync_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf,
                   dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fsync_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
        struct mtdata_fd       *pfd       = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;
        if (!local)
            goto uncached;

		if(op_ret < 0)
            goto uncached;

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;

#if DEBUG
有待调优，直接赋值可能存在问题， 参照md_cache层有对time的检查
#endif
		LOCK(&fsnd->lock);
		{
			iatt_to_stat(postbuf,&fsnd->stat);
		}
		UNLOCK(&fsnd->lock);
		
uncached:

        MTDATA_STACK_UNWIND (fsync, frame, op_ret, op_errno, prebuf, postbuf,
                             xdata);
        return 0;
}

int32_t
metadata_fstat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *buf,
                   dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fstat_cbk  op_ret=[%d]", op_ret);

        STACK_UNWIND_STRICT (fstat, frame, op_ret, op_errno, buf, xdata);
        return 0;
}

int32_t
metadata_opendir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, fd_t *fd,
                     dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_opendir_cbk  op_ret=[%d]", op_ret);

        STACK_UNWIND_STRICT (opendir, frame, op_ret, op_errno, fd, xdata);
        return 0;
}

int32_t
metadata_fsyncdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fsyncdir_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
        metadata_local_t       *local     = NULL;
        struct mtdata_fd       *pfd       = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;
        if (!local)
            goto uncached;

		if(op_ret < 0)
            goto uncached;

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

		op_ret = 0;
uncached:

        MTDATA_STACK_UNWIND (fsyncdir, frame, op_ret, op_errno, xdata);
        return 0;
}

int32_t
metadata_statfs_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct statvfs *buf,
                    dict_t *xdata)
{
        STACK_UNWIND_STRICT (statfs, frame, op_ret, op_errno, buf, xdata);
        return 0;
}


int32_t
metadata_setxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_setxattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;

        if (!local)
            goto uncached;

		if(op_ret < 0)
            goto uncached;

		dict_del (local->xattr, GFID_XATTR_KEY);

		fsnd = get_next_fsnode(priv->table, local->loc.gfid);
		if(!fsnd){
			gf_log (this->name, GF_LOG_ERROR, "metadata_setxattr_cbk uncached falied!");
			goto uncached;
		}
	
/*posix更新成功后，更新缓存 */
		if(local->xattr){
			op_ret = fsnode_xattr_upd(this, &local->loc, local->xattr, fsnd);
			//gf_log (this->name, GF_LOG_ERROR, "metadata_setxattr_cbk op_ret=[%d], op_errno=[%d]", op_ret ,op_errno); 
		}

		if (op_ret < 0)
			op_errno = -op_ret;

//gf_log (this->name, GF_LOG_ERROR, "metadata_setxattr_cbk op_ret=[%d], op_errno=[%d]", op_ret ,op_errno); 

uncached:

        MTDATA_STACK_UNWIND(setxattr, frame, op_ret, op_errno, xdata);
        return 0;
}


int32_t
metadata_fsetxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                       int32_t op_ret, int32_t op_errno,
                       dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fsetxattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        struct mtdata_fd       *pfd       = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		if(op_ret < 0)
            goto uncached;

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;
        if (!local)
            goto uncached;


		dict_del (local->xattr, GFID_XATTR_KEY);
        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;
gf_log (this->name, GF_LOG_INFO, "Test metadata_fsetxattr fsnd->gfid=[%02x%02x]", fsnd->gfid[14],fsnd->gfid[15]);

/*posix更新成功后，更新缓存 */
		if(local->xattr){
			op_ret = fsnode_xattr_upd(this, &local->loc, local->xattr, fsnd);
			gf_log (this->name, GF_LOG_ERROR, "metadata_fsetxattr_cbk op_ret=[%d], op_errno=[%d]", op_ret ,op_errno); 
		}

		if (op_ret < 0)
			op_errno = -op_ret;

uncached:

        MTDATA_STACK_UNWIND(fsetxattr, frame, op_ret, op_errno, xdata);

        return 0;
}



int32_t
metadata_fgetxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                       int32_t op_ret, int32_t op_errno, dict_t *dict,
                       dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fgetxattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        struct mtdata_fd       *pfd       = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        local = frame->local;
        if (!local)
            goto uncached;

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

		fsnd = pfd->fsnd;
		if(!fsnd){
			gf_log (this->name, GF_LOG_ERROR, "metadata_getxattr_cbk uncached falied!");
			goto uncached;
		}
	
		if(dict){
			fsnode_xattr_upd(this, NULL, dict, fsnd);
		}


        MTDATA_STACK_UNWIND(getxattr, frame, op_ret, op_errno, dict, xdata);
        return 0;

uncached:

        STACK_UNWIND_STRICT (fgetxattr, frame, op_ret, op_errno, dict, xdata);
        return 0;
}


int32_t
metadata_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, dict_t *dict,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_getxattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        local = frame->local;
        if (!local)
            goto uncached;

		fsnd = metadata_get_fsnode(priv->table, &local->loc);
		if(!fsnd){
			gf_log (this->name, GF_LOG_ERROR, "metadata_getxattr_cbk uncached falied!");
			goto uncached;
		}
	
		if(dict){
			fsnode_xattr_upd(this, &local->loc, dict, fsnd);
		}


        MTDATA_STACK_UNWIND(getxattr, frame, op_ret, op_errno, dict, xdata);
        return 0;

uncached:
        STACK_UNWIND_STRICT(getxattr, frame, op_ret, op_errno, dict, xdata);
        return 0;
}

/**
 *  * add_array - add two arrays of 32-bit numbers (stored in network byte order)
 *   * dest = dest + src
 *    * @count: number of 32-bit numbers
 *     * FIXME: handle overflow
 *      */

static char *mtdata_marker_xattrs[] = {"trusted.zefs.quota.*",
                         "trusted.zefs.*.xtime",
                         NULL};

static void
__add_array (int32_t *dest, int32_t *src, int count)
{
        int     i = 0;
        int32_t destval = 0;
        for (i = 0; i < count; i++) {
                destval = ntoh32 (dest[i]);
                if (destval == 0xffffffff)
                        continue;
                dest[i] = hton32 (destval + ntoh32 (src[i]));
        }
}

static void
__or_array (int32_t *dest, int32_t *src, int count)
{
        int i = 0;
        for (i = 0; i < count; i++) {
                dest[i] = hton32 (ntoh32 (dest[i]) | ntoh32 (src[i]));
        }
}

static void
__and_array (int32_t *dest, int32_t *src, int count)
{
        int i = 0;
        for (i = 0; i < count; i++) {
                dest[i] = hton32 (ntoh32 (dest[i]) & ntoh32 (src[i]));
        }
}

static void
__add_long_array (int64_t *dest, int64_t *src, int count)
{
        int i = 0;
        for (i = 0; i < count; i++) {
                dest[i] = hton64 (ntoh64 (dest[i]) + ntoh64 (src[i]));
        }
}
static int
_metadata_handle_xattr_keyvalue_pair (dict_t *d, char *k, data_t *v,
                                   void *tmp)
{
        int                   size     = 0;
        int                   count    = 0;
        int                   op_ret   = 0;
        int                   op_errno = 0;
        gf_xattrop_flags_t    optype   = 0;
        char                 *array    = NULL;
        fsnode               *fsnd     = NULL;
        xlator_t             *this     = NULL;
        metadata_xattr_filler_t *filler   = NULL;

        filler = tmp;

        optype = (gf_xattrop_flags_t)(filler->flags);
        this = filler->this;
        fsnd = filler->fsnd;

        count = v->len;
        array = GF_CALLOC (count, sizeof (char), gf_metadata_mt_char);

        LOCK (&fsnd->lock);
        {
				if(fsnd)
                	size = fsnode_xattr_from_key_get_value(filler->fsnd, k,
                                              (char *)array, v->len);
                op_errno = errno;
                if ((size == -1) && (op_errno != ENODATA) &&
                    (op_errno != ENODATA)) {
                        if (op_errno == ENOTSUP) {
                                GF_LOG_OCCASIONALLY(gf_metadata_xattr_enotsup_log,
                                                    this->name, GF_LOG_WARNING,
                                                    "Extended attributes not "
                                                    "supported by filesystem");
                        } else if (op_errno != ENOENT ||
                                   !metadata_special_xattr (mtdata_marker_xattrs,
                                                         k)) {
                                if (filler->loc)
                                        gf_log (this->name, GF_LOG_ERROR,
                                                "getxattr failed on %s while doing "
                                                "xattrop: Key:%s (%s)",
                                                filler->loc->path,
                                                k, strerror (op_errno));
                                else
                                        gf_log (this->name, GF_LOG_ERROR,
                                                "fgetxattr failed on fd=%d while doing "
                                                "xattrop: Key:%s (%s)",
                                                filler->fd,
                                                k, strerror (op_errno));
                        }

                        op_ret = -1;
                        goto unlock;
                }

                switch (optype) {

                case GF_XATTROP_ADD_ARRAY:
                        __add_array ((int32_t *) array, (int32_t *) v->data,
                                     v->len / 4);
                        break;

                case GF_XATTROP_ADD_ARRAY64:
                        __add_long_array ((int64_t *) array, (int64_t *) v->data,
                                          v->len / 8);
                        break;

                case GF_XATTROP_OR_ARRAY:
                        __or_array ((int32_t *) array,
                                    (int32_t *) v->data,
                                    v->len / 4);
                        break;

                case GF_XATTROP_AND_ARRAY:
                        __and_array ((int32_t *) array,
                                     (int32_t *) v->data,
                                     v->len / 4);
                        break;

                default:
                        gf_log (this->name, GF_LOG_ERROR,
                                "Unknown xattrop type (%d) on %s. Please send "
                                "a bug report to zecloud-devel@nongnu.org",
                                optype, filler->loc->path);
                        op_ret = -1;
                        op_errno = EINVAL;
                        goto unlock;
                }

				size = fsnode_setxattr(fsnd, k, array, v->len, 0);
/*
                if (filler->loc) {
                        size = sys_lsetxattr (filler->real_path, k, array,
                                              v->len, 0);
                } else {
                        size = sys_fsetxattr (filler->fd, k, (char *)array,
                                              v->len, 0);
                }
*/
        }
unlock:
        UNLOCK (&fsnd->lock);

        if (op_ret == -1)
                goto out;

        op_errno = errno;
        if (size == -1) {
                if (filler->loc)
                        gf_log (this->name, GF_LOG_ERROR,
                                "setxattr failed on %s while doing xattrop: "
                                "key=%s (%s)", filler->loc->path,
                                k, strerror (op_errno));
                else
                        gf_log (this->name, GF_LOG_ERROR,
                                "fsetxattr failed on fd=%d while doing xattrop: "
                                "key=%s (%s)", filler->fd,
                                k, strerror (op_errno));

                op_ret = -1;
                goto out;
        } else {
                size = dict_set_bin (d, k, array, v->len);

                if (size != 0) {
                        if (filler->loc)
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "dict_set_bin failed (path=%s): "
                                        "key=%s (%s)", filler->loc->path,
                                        k, strerror (-size));
                        else
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "dict_set_bin failed (fd=%d): "
                                        "key=%s (%s)", filler->fd,
                                        k, strerror (-size));

                        op_ret = -1;
                        op_errno = EINVAL;
                        goto out;
                }
                array = NULL;
        }

        array = NULL;

out:
        return op_ret;

}

/**
 *  * xattrop - xattr operations - for internal use by ZeFS
 *  * @optype: ADD_ARRAY:
 *  *          dict should contain:
 *  *          "key" ==> array of 32-bit numbers
 *  */
int32_t 
metadata_do_xattrop (call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd,
            gf_xattrop_flags_t optype, dict_t *xattr)
{
        int                       op_ret    = 0;
        int                       op_errno  = 0;
        int                      _fd        = -1;
        struct mtdata_fd         *pfd       = NULL;
        metadata_xattr_filler_t   filler    = {0,};
		metadata_private_t       *priv      = NULL;
		fsnode                   *fsnd      = NULL;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (xattr, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (this->private, out);

		priv = this->private;
		
        if (fd) {
                op_ret = metadata_fd_ctx_get (fd, this, &pfd);
                if (op_ret < 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to get pfd from fd=%p",
                                fd);
                        op_errno = EBADFD;
                        goto out;
                }
                _fd = pfd->fd;
        }

        if (loc && !uuid_is_null (loc->gfid)){
				fsnd = metadata_get_fsnode(priv->table, loc);
				if(!fsnd){
					op_errno = ENOENT;
					goto out;
				}
		}

        if (fd) {
                fsnd = pfd->fsnd;
        }

        filler.this = this;
        filler.fd = _fd;
        filler.loc = loc;
        //filler.real_path = real_path;
        filler.flags = (int)optype;
        filler.fsnd= fsnd;

        op_ret = dict_foreach (xattr, _metadata_handle_xattr_keyvalue_pair,
                               &filler);

out:

        MTDATA_STACK_UNWIND (xattrop, frame, op_ret, op_errno, xattr, NULL);
        return 0;

}
int32_t
metadata_xattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, dict_t *dict,
                     dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_xattrop_cbk  op_ret=[%d]", op_ret);
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

        local = frame->local;
		if(!local)
			goto uncached;

		metadata_do_xattrop (frame, this, &local->loc, NULL, local->optype, local->xattr);
        return 0;

uncached:
		op_ret = -1;
        MTDATA_STACK_UNWIND (xattrop, frame, op_ret, op_errno, dict, xdata);
        return 0;
}

int32_t
metadata_fxattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, dict_t *dict,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fxattrop_cbk  op_ret=[%d]", op_ret);
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

        local = frame->local;
		if(!local)
			goto uncached;

		metadata_do_xattrop (frame, this, NULL, local->fd, local->optype, local->xattr);
		return 0;

uncached:
		op_ret = -1;
        MTDATA_STACK_UNWIND (fxattrop, frame, op_ret, op_errno, dict, xdata);
        return 0;
}


int32_t
metadata_removexattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                         int32_t op_ret, int32_t op_errno,
                         dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_removexattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(op_ret < 0)
            goto uncached;

        local = frame->local;
        if (!local)
            goto uncached;

        if (!strcmp (GFID_XATTR_KEY, local->key)) {
                gf_log (this->name, GF_LOG_WARNING, "Remove xattr called"
                        " on gfid for file %s", local->loc.path);
                op_ret = -1;
                goto uncached;
        }

		fsnd = get_next_fsnode(priv->table, local->loc.gfid);
		if(!fsnd){
			gf_log (this->name, GF_LOG_ERROR, "metadata_setxattr_cbk uncached falied!");
			goto uncached;
		}
	
/*posix更新成功后，更新缓存 */
		if(local->key){
			op_ret = fsnode_xattr_del_forupd(local->key, fsnd);
			if(op_ret < 0)
				goto uncached;
		}

		op_ret = 0;
uncached:
        MTDATA_STACK_UNWIND(removexattr, frame, op_ret, op_errno, xdata);
        return 0;
}


int32_t
metadata_fremovexattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                          int32_t op_ret, int32_t op_errno,
                          dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fremovexattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        struct mtdata_fd       *pfd       = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		if(op_ret < 0)
            goto uncached;

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;
        if (!local)
            goto uncached;

        if (!strcmp (GFID_XATTR_KEY, local->key)) {
                gf_log (this->name, GF_LOG_WARNING, "Remove xattr called"
                        " on gfid for file %s", local->loc.path);
                op_ret = -1;
                goto uncached;
        }

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;
gf_log (this->name, GF_LOG_INFO, "Test metadata_fsetattr fsnd->gfid=[%02x%02x]", fsnd->gfid[14],fsnd->gfid[15]);
/*posix更新成功后，更新缓存 */
		if(local->key){
			op_ret = fsnode_xattr_del_forupd(local->key, fsnd);
			if(op_ret < 0)
				goto uncached;
		}

		op_ret = 0;

uncached:
        MTDATA_STACK_UNWIND (fremovexattr, frame, op_ret, op_errno, xdata);
        return 0;
}

int32_t
metadata_lk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct gf_flock *lock,
                dict_t *xdata)
{
        STACK_UNWIND_STRICT (lk, frame, op_ret, op_errno, lock, xdata);
        return 0;
}

int32_t
metadata_inodelk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno,
                     dict_t *xdata)
{
        STACK_UNWIND_STRICT (inodelk, frame, op_ret, op_errno, xdata);
        return 0;
}


int32_t
metadata_finodelk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno,
                      dict_t *xdata)
{
        STACK_UNWIND_STRICT (finodelk, frame, op_ret, op_errno, xdata);
        return 0;
}

int32_t
metadata_entrylk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno,
                     dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_entrylk_cbk  op_ret=[%d]", op_ret);
        STACK_UNWIND_STRICT (entrylk, frame, op_ret, op_errno, xdata);
        return 0;
}

int32_t
metadata_fentrylk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fentrylk_cbk  op_ret=[%d]", op_ret);

        STACK_UNWIND_STRICT (fentrylk, frame, op_ret, op_errno, xdata);
        return 0;
}


int32_t
metadata_rchecksum_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                       int32_t op_ret, int32_t op_errno, uint32_t weak_checksum,
                       uint8_t *strong_checksum,
                       dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_rchecksum_cbk  op_ret=[%d]", op_ret);

        STACK_UNWIND_STRICT (rchecksum, frame, op_ret, op_errno, weak_checksum,
                             strong_checksum, xdata);
        return 0;
}


int32_t
metadata_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, gf_dirent_t *entries,
                     dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata readdir_cbk  op_ret=[%d]", op_ret);
        STACK_UNWIND_STRICT (readdir, frame, op_ret, op_errno, entries, xdata);
        return 0;
}


int32_t
metadata_readdirp_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, gf_dirent_t *entries,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata readdirp_cbk  op_ret=[%d]", op_ret);
        STACK_UNWIND_STRICT (readdirp, frame, op_ret, op_errno, entries, xdata);
        return 0;
}

int32_t
metadata_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, struct iatt *statpre,
                     struct iatt *statpost,
                     dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_setattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
        metadata_local_t       *local     = NULL;
		
		if(op_ret < 0)
            goto uncached;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;

        if (!local)
            goto uncached;

		op_ret = metadata_fsnode_stat_upd(priv->table, local->loc.gfid, statpost);
		if (op_ret < 0)
			op_errno = -op_ret;

uncached:

        MTDATA_STACK_UNWIND(setattr, frame, op_ret, op_errno, statpre,
                             statpost, xdata);
        return 0;
}

int32_t
metadata_fsetattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, struct iatt *statpre,
                      struct iatt *statpost,
                      dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fsetattr_cbk  op_ret=[%d]", op_ret);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        struct mtdata_fd       *pfd       = NULL;
        metadata_local_t       *local     = NULL;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);

		if(op_ret < 0)
            goto uncached;

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = frame->local;
        if (!local)
            goto uncached;

        op_ret = metadata_fd_ctx_get(local->fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", local->fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;
gf_log (this->name, GF_LOG_INFO, "Test metadata_fsetattr fsnd->gfid=[%02x%02x]", fsnd->gfid[14],fsnd->gfid[15]);

		LOCK(&fsnd->lock);
		{
			iatt_to_stat(statpost,&fsnd->stat);
		}
		UNLOCK(&fsnd->lock);

		op_ret = 0;

uncached:

        MTDATA_STACK_UNWIND (fsetattr, frame, op_ret, op_errno, statpre,
                             statpost, xdata);
        return 0;
}

int32_t
metadata_getspec_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, char *spec_data)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata getspec " );

        STACK_UNWIND_STRICT (getspec, frame, op_ret, op_errno, spec_data);
        return 0;
}

int32_t
metadata_fgetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                          const char *name, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata fgetxattr name=[%s]" ,name);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        struct mtdata_fd       *pfd       = NULL;
		char                    key[4096] = {0,};
		dict_t *                dict      = NULL;
		int                     op_ret    = -1;
        int32_t                 op_errno  = 0;
        int32_t                 size      = 0;
		metadata_local_t *local = NULL;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (fd, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = metadata_local_get (frame);
		local->fd = fd_ref (fd);

		if(!priv->load_metadata_complete)
			goto uncached;

        op_ret = metadata_fd_ctx_get(fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;
gf_log (this->name, GF_LOG_INFO, "Test metadata_fgetxattr fsnd->gfid=[%02x%02x]", fsnd->gfid[14],fsnd->gfid[15]);
        dict = get_new_dict ();
        if (!dict) {
                goto uncached;
        }

        if (name && !strcmp (name, ZEFS_OPEN_FD_COUNT)) {
                op_ret = dict_set_uint32 (dict, (char *)name, 1);
                if (op_ret < 0)
                        gf_log (this->name, GF_LOG_WARNING,
                                "Failed to set dictionary value for %s",
                                name);
                goto done;
        }
		if(name){
			strcpy (key, name);
            size = fsnode_xattr_get_value(this, dict, 
										key, fsnd);
			if(size <0)
				goto uncached;
			goto done;
		}
		//list all xattr 
		size = fsnode_list_all_xattr(this, fsnd, dict);
		if(size < 0)
			goto uncached;

done:
gf_log (this->name, GF_LOG_INFO, "metadata_fgetxattr size=[%d]", size );
        op_ret = size;

        if (dict) {
                dict_del (dict, GFID_XATTR_KEY);
                dict_ref (dict);
        }

        MTDATA_STACK_UNWIND(fgetxattr, frame, op_ret, op_errno, dict, xdata);
        if (dict)
                dict_unref (dict);

        return 0;

uncached:
        STACK_WIND (frame, metadata_fgetxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fgetxattr, fd, name, xdata);
        return 0;
}

int32_t
metadata_fsetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                          dict_t *dict, int32_t flags, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata fsetxattr " );
gf_log ("", GF_LOG_ERROR, "key=[%s], value=[%02x%02x], flags=[%d]", dict->members_list->key, 
			dict->members_list->value->data[2], dict->members_list->value->data[3], flags);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

		local->fd = fd_ref (fd);

		if(dict)
	        local->xattr = dict_ref (dict);

        STACK_WIND (frame, metadata_fsetxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fsetxattr, fd, dict, flags, xdata);
        return 0;
}

int32_t
metadata_setxattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                         dict_t *dict, int32_t flags, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata setxattr loc->path =[%s]", loc->path);
gf_log ("", GF_LOG_ERROR, "key=[%s], value=[%02x%02x], flags=[%d]", dict->members_list->key, 
			dict->members_list->value->data[2], dict->members_list->value->data[3], flags);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
		if(dict)
	        local->xattr = dict_ref (dict);

        STACK_WIND (frame, metadata_setxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->setxattr, loc, dict, flags, xdata);
        return 0;
}

int32_t
metadata_statfs (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata statfs loc->path =[%s]", loc->path);

        STACK_WIND (frame, metadata_statfs_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->statfs, loc, xdata);
        return 0;
}

int32_t
metadata_fsyncdir (call_frame_t *frame, xlator_t *this, fd_t *fd,
                         int32_t flags, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata fsyncdir flags =[%d]", flags);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);
 
		local->fd = fd_ref (fd);

        STACK_WIND (frame, metadata_fsyncdir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fsyncdir, fd, flags, xdata);
        return 0;
}

int32_t
metadata_opendir (call_frame_t *frame, xlator_t *this, loc_t *loc,
                        fd_t *fd, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata opendir loc->path=[%s], fd->inode->gfid=[%02x%02x]",
				loc->path, fd->inode->gfid[14], fd->inode->gfid[15]);
		int32_t               op_ret   = -1;
		int32_t               op_errno = 0;
		fsnode               *fsnd     = NULL;
        metadata_private_t   *priv     = NULL;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
		VALIDATE_OR_GOTO (loc, uncached);
		VALIDATE_OR_GOTO (loc->path, uncached);
        VALIDATE_OR_GOTO (fd, uncached);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

		fsnd = metadata_get_fsnode(priv->table, loc);
		if(!fsnd){
			gf_log (this->name, GF_LOG_WARNING, "path=[%s]", loc->path);
			goto uncached;
		}

		op_ret = metadata_fd_virt_set(this, priv->table, 
								fsnd, fd);
		if(op_ret < 0){
			gf_log ("", GF_LOG_INFO, "metadata cached not found  loc->path=[%s]", loc->path);
			goto uncached;
		}
			
        MTDATA_STACK_UNWIND(opendir, frame, op_ret, op_errno, fd, NULL);
        return 0;

uncached:
        STACK_WIND (frame, metadata_opendir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->opendir, loc, fd, xdata);
        return 0;
}

/* Add by hf@20150601 for opendir fd is virtual */
int32_t
metadata_releasedir (xlator_t *this,
                  fd_t *fd)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata releasedir ");
        metadata_private_t   *priv     = NULL;
        struct mtdata_fd     *pfd      = NULL;
        uint64_t              tmp_pfd  = 0;
        int                   ret      = 0;

        priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        ret = fd_ctx_del (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "pfd from fd=%p is NULL", fd);
                goto uncached;
        }

        pfd = (struct mtdata_fd *)(long)tmp_pfd;
        if (!pfd->fd) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd->dir is NULL for fd=%p", fd);
                goto uncached;
        }
        LOCK(&priv->table->lock);
        {
			priv->table->virfd_num = 4;
        }
        UNLOCK(&priv->table->lock);

uncached:
		return 0;
}
/* End add */

int32_t 
metadata_release (xlator_t *this, fd_t *fd)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata release ");
        metadata_private_t   *priv     = NULL;
        struct mtdata_fd     *pfd      = NULL;
        uint64_t              tmp_pfd  = 0;
        int                   ret      = 0;

        priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        ret = fd_ctx_del (fd, this, &tmp_pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "pfd from fd=%p is NULL", fd);
                goto uncached;
		}
        pfd = (struct mtdata_fd *)(long)tmp_pfd;

        if (pfd->fsnd) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd->fsnd is %p (not NULL) for file fd=%p",
                        pfd->fsnd, fd);
			pfd->fsnd = NULL;
        }
//有待调整， 可以吧内存释放放到一个进程中，专门做 fefer to posix init()
//释放mtdata_fd在open时申请的堆空间 
uncached:
		return 0;
}
// stack_wind function

int32_t
metadata_fstat (call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_fstat fd->pid=[%ld]", fd->pid);
		metadata_private_t     *priv      = NULL;
		fsnode                 *fsnd      = NULL;
        struct mtdata_fd       *pfd       = NULL;
		struct iatt             stbuf     = {0, };
		int                     op_ret    = -1;
        int32_t                 op_errno  = 0;
		
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (fd, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        op_ret = metadata_fd_ctx_get(fd, this, &pfd);
        if (op_ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -op_ret;
                goto uncached;
        }

        fsnd = pfd->fsnd;
gf_log (this->name, GF_LOG_INFO, "Test metadata_fstat fsnd->gfid=[%02x%02x]", fsnd->gfid[14],fsnd->gfid[15]);

		iatt_from_stat(&stbuf,&fsnd->stat);
		op_ret = 0;

        MTDATA_STACK_UNWIND(fstat, frame, op_ret, op_errno, &stbuf, NULL);
        return 0;

uncached:
		gf_log (this->name, GF_LOG_INFO, "++Goto posix fstat uncache !" );
        STACK_WIND (frame, metadata_fstat_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fstat, fd, xdata);
        return 0;
}

int32_t
metadata_fsync (call_frame_t *frame, xlator_t *this, fd_t *fd,
                      int32_t flags, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "00-metadata fsync flags=[%d]", flags);

		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);
 
		local->fd = fd_ref (fd);

        STACK_WIND (frame, metadata_fsync_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fsync, fd, flags, xdata);
        return 0;
}

int32_t
metadata_flush (call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *xdata)
{
        STACK_WIND (frame, metadata_flush_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->flush, fd, xdata);
        return 0;
}

int32_t
metadata_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
                       struct iovec *vector, int32_t count, off_t off,
                       uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "00-metadata writev count=[%d] off=[%ld], flags=[%d]", count, off, flags);

		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);
 
		local->fd = fd_ref (fd);

        STACK_WIND (frame, metadata_writev_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->writev, fd, vector, count, off,
                    flags, iobref, xdata);
        return 0;
}

int32_t
metadata_readv (call_frame_t *frame, xlator_t *this, fd_t *fd,
                      size_t size, off_t offset, uint32_t flags, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "00-metadata readv size=[%ld], offset=[%ld], flags=[%d]",size, offset, flags);

		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);
 
		local->fd = fd_ref (fd);

        STACK_WIND (frame, metadata_readv_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->readv, fd, size, offset, flags, xdata);
        return 0;
}


int32_t
metadata_open (call_frame_t *frame, xlator_t *this, loc_t *loc,
                     int32_t flags, fd_t *fd, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "00-metadata open path=[%s] loc->gfid=[%02x%02x]",
			loc->path, loc->gfid[14], loc->gfid[15]);

		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);
 
        loc_copy (&local->loc, loc);
		local->fd = fd_ref (fd);

        STACK_WIND (frame, metadata_open_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->open, loc, flags, fd, xdata);
        return 0;
}

int32_t
metadata_create (call_frame_t *frame, xlator_t *this, loc_t *loc,
                       int32_t flags, mode_t mode, mode_t umask, fd_t *fd,
                       dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_create  path=[%s],loc->name=[%s]", loc->path ,loc->name);
        metadata_private_t     *priv      = NULL;
		priv = this->private;
		
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
		if(xdata)
	    	local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_create_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->create, loc, flags, mode, umask,
                    fd, xdata);
        return 0;
}

int32_t
metadata_link (call_frame_t *frame, xlator_t *this, loc_t *oldloc,
                     loc_t *newloc, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_link oldloc->path=[%s],name=[%s], newloc->path=[%s],name=[%s]", 
				oldloc->path, newloc->path, oldloc->name, newloc->name);
        metadata_private_t     *priv      = NULL;
		priv = this->private;
		
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, oldloc);
        loc_copy (&local->loc2, newloc);
		if(xdata)
	        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_link_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->link, oldloc, newloc, xdata);
        return 0;
}

int32_t
metadata_rename (call_frame_t *frame, xlator_t *this, loc_t *oldloc,
                       loc_t *newloc, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_rename oldloc->path=[%s],oldloc->name=[%s], \
newloc->path=[%s], newloc->name=[%s],oldloc->pargfid=[%02x%02x], newloc->pargfid=[%02x%02x]", 
				oldloc->path,oldloc->name, newloc->path, newloc->name, 
				oldloc->pargfid[14], oldloc->pargfid[15],
				newloc->pargfid[14], newloc->pargfid[15]);

		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, oldloc);
        loc_copy (&local->loc2, newloc);
		if(xdata)
	        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_rename_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->rename, oldloc, newloc, xdata);
        return 0;
}


int
metadata_symlink (call_frame_t *frame, xlator_t *this,
                        const char *linkpath, loc_t *loc, mode_t umask,
                        dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_symlink loc->path=[%s], linkpath=[%s]", loc->path, linkpath);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
		local->linkname = gf_strdup (linkpath);

		if(xdata)
	        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_symlink_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->symlink, linkpath, loc, umask,
                    xdata);
        return 0;
}

int32_t
metadata_rmdir (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      int flags, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_rmdir  path=[%s],loc->name=[%s]", loc->path ,loc->name);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);

        STACK_WIND (frame, metadata_rmdir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->rmdir, loc, flags, xdata);
        return 0;
}

int32_t
metadata_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc,
                       int xflag, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_unlink path=[%s],loc->name=[%s]", loc->path ,loc->name);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);

        STACK_WIND (frame, metadata_unlink_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->unlink, loc, xflag, xdata);
        return 0;
}

int
metadata_mkdir (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      mode_t mode, mode_t umask, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_mkdir  path=[%s],loc->name=[%s]", loc->path ,loc->name);
if(xdata->members_list)
gf_log ("", GF_LOG_ERROR, "------------key=[%s], value=[%02x%02x]", xdata->members_list->key, 
			xdata->members_list->value->data[2], xdata->members_list->value->data[3]);
        metadata_private_t     *priv      = NULL;
		priv = this->private;
		
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_mkdir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->mkdir, loc, mode, umask, xdata);
        return 0;
}


int
metadata_mknod (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      mode_t mode, dev_t rdev, mode_t umask, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_mkmod loc->path=%s, loc->gfid=[%02x%02x], loc->pargfid=[%02x%02x]", loc->path,
				loc->gfid[14], loc->gfid[15], loc->pargfid[14], loc->pargfid[15]);

		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_mknod_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->mknod, loc, mode, rdev, umask,
                    xdata);
        return 0;
}

int32_t
metadata_readlink (call_frame_t *frame, xlator_t *this, loc_t *loc,
                         size_t size, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_readlink loc->path=%s, size=[%ld]", loc->path, size);
        char *  lkname    = NULL;
        int32_t op_ret    = -1;
        int32_t op_errno  = 0;
        //char *  real_path = NULL;
        struct iatt stbuf = {0,};
        //DECLARE_OLD_FS_ID_VAR;
        fsnode                 *fsnd      = NULL;
        fsedge                 *fseg      = NULL;
        metadata_private_t     *priv      = NULL;
		
		priv = this->private;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (loc, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        VALIDATE_OR_GOTO (priv, uncached);


        //SET_FS_ID (frame->root->uid, frame->root->gid);

        lkname = alloca (size + 1);

		op_ret = metadata_inode_iatt_get (priv->table, loc, &stbuf);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, (op_errno == ENOENT)?
                        GF_LOG_DEBUG:GF_LOG_ERROR,
                        "lstat on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto uncached;
        }

		fsnd = metadata_get_fsnode(priv->table, loc);
        if (!fsnd) {
                op_errno = errno;
                gf_log (this->name, (op_errno == ENOENT)?
                        GF_LOG_DEBUG:GF_LOG_ERROR,
                        "lstat on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto uncached;
        }

		fseg = list_entry(fsnd->parents.next, struct _fsedge, parent_list);
		if(IA_ISLNK(ia_type_from_st_mode (fsnd->stat.st_mode)) && 
				fseg->linkname ){
			strcpy(lkname, fseg->linkname);
		}

		op_ret = strlen(lkname);
        lkname[op_ret] = 0;
gf_log (this->name, GF_LOG_INFO, "Test for readlink lkname=[%s], op_ret=[%d]", lkname, op_ret);

        //SET_TO_OLD_FS_ID ();

        MTDATA_STACK_UNWIND(readlink, frame, op_ret, op_errno, lkname, &stbuf, xdata);
		return 0;
        

uncached:
		gf_log (this->name, GF_LOG_INFO, "++Goto posix readlink  op_ret=[%d]!", op_ret);
        STACK_WIND (frame, metadata_readlink_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->readlink, loc, size, xdata);
        return 0;
}


int32_t
metadata_access (call_frame_t *frame, xlator_t *this, loc_t *loc,
                       int32_t mask, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "Begin goto metadata_access loc->path=%s, gfid=[%02x%02x],mask=[%d]", 
		loc->path,loc->gfid[14], loc->gfid[15], mask);

#if 0
        int32_t                 op_ret    = -1;
        int32_t                 op_errno  = 0;
		fsnode                 *fsnd      = NULL;
        metadata_private_t     *priv      = NULL;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (loc, uncached);

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

		fsnd = metadata_get_fsnode(priv->table, loc);
        if (!fsnd) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "access failed on %s: %s",
                        loc->path, strerror (op_errno));
                goto uncached;
		}

		ia_prot_t  st_port;
		st_port = ia_prot_from_st_mode (fsnd->stat.st_mode);
		int mode = mask & 07;
        op_ret = access (loc->path, mask & 07);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, GF_LOG_ERROR, "access failed on %s: %s",
                        loc->path, strerror (op_errno));
                goto uncached;
        }
        op_ret = 0;

        MTDATA_STACK_UNWIND(access, frame, op_ret, op_errno, xdata);
        return 0;

uncached:
#endif

        STACK_WIND (frame, metadata_access_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->access, loc, mask, xdata);
        return 0;
}

int32_t
metadata_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd,
                          off_t offset, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata ftruncate  offset=[%ld] ", offset);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

		local->fd = fd_ref (fd);
		if(xdata)
	        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_ftruncate_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->ftruncate, fd, offset, xdata);
        return 0;
}

int32_t
metadata_getxattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                         const char *name, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "metadata getxattr path=[%s],name=[%s], loc->gfid=[%02x%02x%02x%02x], loc->pargfid=[%02x%02x%02x%02x]",
            loc->path,name ,
            loc->gfid[12], loc->gfid[13],loc->gfid[14], loc->gfid[15],                                                                    
            loc->pargfid[12], loc->pargfid[13],loc->pargfid[14], loc->pargfid[15]);                                                       

		metadata_private_t         *priv     = NULL;
		dict_t                     *xattr    = NULL;
		fsnode                     *fsnd     = NULL;
		int32_t                     op_ret   = -1;
        int32_t                     op_errno = 0;
		metadata_local_t *local = NULL;

		//DECLARE_OLD_FS_ID_VAR;
        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (loc, uncached);

		//SET_FS_ID (frame->root->uid, frame->root->gid);  //??

		priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        local = metadata_local_get (frame);
        loc_copy (&local->loc, loc);
		if(name)
			local->key = gf_strdup (name);

		fsnd = metadata_get_fsnode(priv->table, loc);
		if(!fsnd){
			gf_log (this->name, GF_LOG_WARNING, "path=[%s]", loc->path);
			goto uncached;
		}

        xattr = dict_new ();
        if (!xattr) {
			op_errno = ENOMEM;
            goto uncached;
        }

		op_ret = metadata_inode_xatt_get(priv->table, loc, xattr, 
									fsnd, (char*)name);
		if(op_ret < 0)
			goto uncached;

		//if name=NULL, list all xattr 
		//if (!xattr || !dict_get (xattr, (char *)name)) {
		if (!xattr) {
			gf_log (this->name, GF_LOG_ERROR, "metadata getxattr path=[%s], name=[%s]", loc->path, name);
			op_ret = -1;
			op_errno = ENODATA;
		}
        //SET_TO_OLD_FS_ID ();
gf_log (this->name, GF_LOG_ERROR, "metadata getxattr op_ret=[%d], op_error=[%d]", op_ret, op_errno);

        MTDATA_STACK_UNWIND(getxattr, frame, op_ret, op_errno, xattr, xdata);

        if (xattr)
                dict_unref (xattr);
        return 0;

uncached:
        //SET_TO_OLD_FS_ID ();
		gf_log (this->name, GF_LOG_INFO, "metadata getxattr uncached path=[%s], name=[%s]", loc->path, name);

        STACK_WIND (frame, metadata_getxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->getxattr, loc, name, xdata);
        return 0;
}


int32_t
metadata_xattrop (call_frame_t *frame, xlator_t *this, loc_t *loc,
                        gf_xattrop_flags_t flags, dict_t *dict, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "metadata xattrop path=[%s], flags=[%d],loc->gfid=[%02x%02x], loc->pargfid=[%02x%02x]",
            loc->path, flags,
            loc->gfid[14], loc->gfid[15],                                                                    
            loc->pargfid[14], loc->pargfid[15]);                                                       
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
	    local->xattr = dict_ref (dict);

        STACK_WIND (frame, metadata_xattrop_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->xattrop, loc, flags, dict, xdata);
        return 0;
}

int32_t
metadata_fxattrop (call_frame_t *frame, xlator_t *this, fd_t *fd,
                         gf_xattrop_flags_t flags, dict_t *dict, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "metadata fxattrop flags=[%d]", flags);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

		local->fd = fd_ref (fd);
	    local->xattr = dict_ref (dict);

        STACK_WIND (frame, metadata_fxattrop_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fxattrop, fd, flags, dict, xdata);
        return 0;
}

int32_t
metadata_removexattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                            const char *name, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata removexattr loc->path =[%s], name=[%s]", loc->path, name);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
		local->key = gf_strdup (name);

        STACK_WIND (frame, metadata_removexattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->removexattr, loc, name, xdata);
        return 0;
}

int32_t
metadata_fremovexattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                             const char *name, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata fremovexattr name=[%s] ", name);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

		local->fd = fd_ref (fd);
		local->key = gf_strdup (name);
		if(xdata)
	        local->xattr = dict_ref (xdata);
        STACK_WIND (frame, metadata_fremovexattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fremovexattr, fd, name, xdata);
        return 0;
}

int32_t
metadata_lk (call_frame_t *frame, xlator_t *this, fd_t *fd,
                   int32_t cmd, struct gf_flock *lock, dict_t *xdata)
{
        STACK_WIND (frame, metadata_lk_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->lk, fd, cmd, lock, xdata);
        return 0;
}


int32_t
metadata_inodelk (call_frame_t *frame, xlator_t *this,
                        const char *volume, loc_t *loc, int32_t cmd,
                        struct gf_flock *lock,
                        dict_t *xdata)
{
        STACK_WIND (frame, metadata_inodelk_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->inodelk,
                    volume, loc, cmd, lock, xdata);
        return 0;
}

int32_t
metadata_finodelk (call_frame_t *frame, xlator_t *this,
                         const char *volume, fd_t *fd, int32_t cmd,
                         struct gf_flock *lock,
                         dict_t *xdata)
{
        STACK_WIND (frame, metadata_finodelk_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->finodelk,
                    volume, fd, cmd, lock, xdata);
        return 0;
}

int32_t
metadata_entrylk (call_frame_t *frame, xlator_t *this,
                        const char *volume, loc_t *loc, const char *basename,
                        entrylk_cmd cmd, entrylk_type type,
                        dict_t *xdata)
{
        STACK_WIND (frame, metadata_entrylk_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->entrylk,
                    volume, loc, basename, cmd, type, xdata);
        return 0;
}

int32_t
metadata_fentrylk (call_frame_t *frame, xlator_t *this,
                         const char *volume, fd_t *fd, const char *basename,
                         entrylk_cmd cmd, entrylk_type type,
                         dict_t *xdata)
{
        STACK_WIND (frame, metadata_fentrylk_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fentrylk,
                    volume, fd, basename, cmd, type, xdata);
        return 0;
}

int32_t
metadata_rchecksum (call_frame_t *frame, xlator_t *this, fd_t *fd,
                          off_t offset, int32_t len,
                          dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata rchecksum  offset=[%ld], len=[%d] ", offset, len);

        STACK_WIND (frame, metadata_rchecksum_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->rchecksum, fd, offset, len, xdata);
        return 0;
}

void
fsnode_conv_entry(fsedge *fseg,  struct dirent  *entry) 
{
//gf_log ("", GF_LOG_INFO, "fsnd->d_type=[%d] ", fseg->d_type);
		entry->d_ino = fseg->d_ino;
		entry->d_off = fseg->d_off;
		entry->d_reclen = fseg->d_len;
		entry->d_type = fseg->d_type;
		strcpy(entry->d_name, fseg->name);
}

int
metadata_fill_readdir ( off_t off, size_t size,
                    gf_dirent_t *entries, xlator_t *this, int32_t skip_dirs, 
					fsnode *fsnd, fsedge  **tmpfseg)
{
        size_t    					filled       = 0;
        //int             			ret          = 0;
        int             			count        = 0;
        char                        entrybuf[sizeof(struct dirent) + 256 + 8];
        struct dirent  		   	   *entry        = NULL;
        int32_t                     this_size    = -1;
        gf_dirent_t                *this_entry   = NULL;
		metadata_private_t         *priv         = NULL;
		fsedge                     *fseg      = NULL;
		
		priv = this->private;
		VALIDATE_OR_GOTO (priv, out);

//gf_log ("", GF_LOG_INFO, "11111111-readdir inode->gfid=[%02x%02x],off=[%ld]",  fd->inode->gfid[14],fd->inode->gfid[15], off);
        if(list_empty(&fsnd->children))
			goto out;

		fseg = *tmpfseg;


		/*不是第一次下发 ,如果链表中最后一个节点的下一个是头节点，就认为遍历结束 */
		if(off && (&fseg->child_list ==  &fsnd->children)){
			gf_log ("", GF_LOG_INFO, "Search fseg over ! !");
			errno = ENOENT;
			goto out;
		}

		while(&fseg->child_list !=  &fsnd->children){
            errno = 0;
			entry = NULL;
//gf_log ("", GF_LOG_INFO, "fseg child fsdnode=[%02x%02x] name=[%s]", fseg->child->gfid[14], fseg->child->gfid[15], fseg->name);

			fsnode_conv_entry(fseg,  (struct dirent *)entrybuf);

			/* 遍历fsnode下所有目录和文件，赋值entry返回 */
			entry = (struct dirent *)entrybuf;
            if (!entry) {   
				gf_log ("", GF_LOG_INFO, "Readir this entry over !");
                break;
            }

            this_size = max (sizeof (gf_dirent_t),
            		sizeof (gfs3_dirplist))
                      + strlen (entry->d_name) + 1;

            if (this_size + filled > size) 
				break;

			if(filled <= size){
                this_entry = gf_dirent_for_name (entry->d_name);

                if (!this_entry) {
                        gf_log (THIS->name, GF_LOG_ERROR,
                                "could not create gf_dirent for entry %s: (%s)",
                                entry->d_name, strerror (errno));
                        goto out;
                }

                this_entry->d_off = entry->d_off;
                this_entry->d_ino = entry->d_ino;
                this_entry->d_type = entry->d_type;

				//把iatt赋值给entry中，到readdirp_fill时就不用再遍历fsedge 有待商定
		   		iatt_from_stat(&this_entry->d_stat, &fseg->child->stat );
       			uuid_copy (this_entry->d_stat.ia_gfid, fseg->child->gfid);

                list_add_tail (&this_entry->list, &entries->list);

				filled += this_size;
                count ++;
			}
			fseg = list_entry(fseg->child_list.next, struct _fsedge, child_list);
			*tmpfseg = fseg;
			//gf_log ("", GF_LOG_INFO, "fseg name=[%s]", (*tmpfseg)->name);
		}

//gf_log ("", GF_LOG_INFO, "count=[%d]", count);
out:
        return count;

}

dict_t *
metadata_entry_xattr_fill (xlator_t *this, inode_t *inode,
                          dict_t *dict, struct iatt *stbuf, 
							fsnode *fsnd)
{
        loc_t  tmp_loc    = {0,};
        /* if we don't send the 'loc', open-fd-count be a problem. */
        tmp_loc.inode = inode;

		return metadata_lookup_xattr_get (this, &tmp_loc,
                                        dict, stbuf, fsnd);

}
int
metadata_readdirp_fill (xlator_t *this , fd_t *fd, gf_dirent_t *entries, dict_t *dict)
{
        gf_dirent_t     *entry    = NULL;
        inode_table_t   *itable   = NULL;
		inode_t         *inode    = NULL;
		uuid_t           gfid;
		fsnode          *fsnd    = NULL;
		metadata_private_t  *priv   = NULL;

		priv = this->private;

		if (list_empty(&entries->list))
			return 0;

        itable = fd->inode->table;
//gf_log (this->name, GF_LOG_INFO, "0000000000000inode->table.name=[%s]", fd->inode->table->name);

	list_for_each_entry (entry, &entries->list, list) {
		memset (gfid, 0, 16);
//gf_log (this->name, GF_LOG_INFO, "6666666666666666666666666666name=[%s][%ld]", entry->d_name,(unsigned long)fd->inode);
		inode = inode_grep (fd->inode->table, fd->inode,
				    entry->d_name);
		if (inode){
			uuid_copy (gfid, inode->gfid);
			fsnd = get_next_fsnode(priv->table, gfid);
//			gf_log (this->name, GF_LOG_INFO, "11111111111111gfid=[%02x%02x],entry->name=[%s]", gfid[14], gfid[15], entry->d_name);
		}else{
			fsnd = get_next_fsnode(priv->table, entry->d_stat.ia_gfid);
			//gf_log (this->name, GF_LOG_INFO, "22222222222222gfid=[%02x%02x],entry->name=[%s]", gfid[14], gfid[15], entry->d_name);
		}

		if(!fsnd){
			gf_log (this->name, GF_LOG_INFO, "gfid=[%02x%02x],entry->name=[%s]", gfid[14], gfid[15], entry->d_name);
			continue;
		}

		if (!inode)
			inode = inode_find (itable, entry->d_stat.ia_gfid);

/*
		if (!inode)
			inode = inode_new (itable);
*/

		entry->inode = inode;

		if (dict) {
            entry->dict = metadata_entry_xattr_fill(this, entry->inode,
                                             dict, &entry->d_stat, fsnd);
			dict_ref (entry->dict);
        }

/*
        entry->d_stat = stbuf;

        if (stbuf.ia_ino)
        		entry->d_ino = stbuf.ia_ino;
*/
		inode = NULL;
	}

//out:
	return 0;
}

int32_t
metadata_do_readdir (call_frame_t *frame, xlator_t *this,
                  fd_t *fd, size_t size, off_t off, int whichop, dict_t *dict)
{
        struct mtdata_fd      *pfd           = NULL;
        int                   ret            = -1;
        int                   count          = 0;
        int32_t               op_ret         = -1;
        int32_t               op_errno       = 0;
        gf_dirent_t           entries;
        int32_t               skip_dirs      = 0;
		fsnode               *fsnd           = NULL;
		fsedge               *fseg           = NULL;
		metadata_private_t   *priv           = NULL;

        VALIDATE_OR_GOTO (frame, out);
        VALIDATE_OR_GOTO (this, out);
        VALIDATE_OR_GOTO (fd, out);

        INIT_LIST_HEAD (&entries.list);

		priv = this->private;
		VALIDATE_OR_GOTO (priv, out);

        ret = metadata_fd_ctx_get (fd, this, &pfd);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "pfd is NULL, fd=%p", fd);
                op_errno = -ret;
                goto out;
        }

        fsnd = pfd->fsnd;
        fseg = pfd->fseg;
//gf_log (this->name, GF_LOG_INFO, "Test metadata_readdir fsnd->gfid=[%02x%02x]", fsnd->gfid[14],fsnd->gfid[15]);


        /* When READDIR_FILTER option is set to on, we can filter out
		* directory's entry from the entry->list.
		**/
        ret = dict_get_int32 (dict, GF_READDIR_SKIP_DIRS, &skip_dirs);

		LOCK (&fd->lock);
		{
		/* posix_fill_readdir performs multiple separate individual
		 * readdir() calls to fill up the buffer.
 		 * 
		 * In case of NFS where the same anonymous FD is shared between
		 * different applications, reading a common directory can
		 * result in the anonymous fd getting re-used unsafely between
		 * the two readdir requests (in two different io-threads).
 		 *
		 * It would also help, in the future, to replace the loop
		 * around readdir() with a single large getdents() call.
		 * */
			count = metadata_fill_readdir (off, size, &entries, this,
					    skip_dirs,fsnd, &fseg);
		}
		UNLOCK (&fd->lock);
        /* pick ENOENT to indicate EOF */
        op_errno = errno;
        op_ret = count;

//gf_log (this->name, GF_LOG_INFO, "Test metadata_readdir fd=[%d], fsnd->gfid=[%02x%02x]", pfd->fd, fsnd->gfid[14],fsnd->gfid[15]);
		pfd->fseg = fseg;
		ret = fd_ctx_set (fd, this, (uint64_t)(long)pfd);
        if (ret){
 				gf_log (this->name, GF_LOG_WARNING,
                				"failed to set the fd context fd=%p", fd);
				goto out;
		}

        if (whichop != GF_FOP_READDIRP)
                goto out;

//gf_log (THIS->name, GF_LOG_INFO, "222000================Test=====count=[%d]", count);
		metadata_readdirp_fill (this, fd, &entries, dict);

out:
        STACK_UNWIND_STRICT (readdir, frame, op_ret, op_errno, &entries, NULL);

		//GF_FREE(tmppfd);
        gf_dirent_free (&entries);

        return 0;
}

int32_t
metadata_readdir (call_frame_t *frame, xlator_t *this, fd_t *fd,
                        size_t size, off_t off,
                        dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata readdir  fd->pid=[%ld], fd->value=[%ld]", fd->pid, fd->_ctx->value1);
		metadata_private_t         *priv = NULL;

		priv = this->private;
		VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

		metadata_do_readdir (frame, this, fd, size, off, GF_FOP_READDIR, xdata);
		return 0;

uncached:
		gf_log (this->name, GF_LOG_INFO, "++Goto posix readdir uncache. ");
        STACK_WIND (frame, metadata_readdir_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->readdir, fd, size, off, xdata);
        return 0;
}

int32_t
metadata_readdirp (call_frame_t *frame, xlator_t *this, fd_t *fd,
                         size_t size, off_t off, dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata readdirp size=[%ld] ", size);
		metadata_private_t         *priv = NULL;

		priv = this->private;
		VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

		metadata_do_readdir (frame, this, fd, size, off, GF_FOP_READDIRP, xdata);
		return 0;

uncached:
		gf_log (this->name, GF_LOG_INFO, "++Goto posix readdirp uncache. ");
        STACK_WIND (frame, metadata_readdirp_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->readdirp, fd, size, off, xdata);
        return 0;
}

int32_t
metadata_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                        struct iatt *stbuf, int32_t valid,
                        dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata setattr valid=[%d] ", valid);

		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);

		if(xdata)
	        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_setattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->setattr, loc, stbuf, valid, xdata);
        return 0;
}

int32_t
metadata_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc,
                         off_t offset,
                         dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata truncate  offset=[%ld] ", offset);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

        loc_copy (&local->loc, loc);
		if(xdata)
	        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_truncate_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->truncate, loc, offset, xdata);
        return 0;
}

int32_t
metadata_stat (call_frame_t *frame, xlator_t *this, loc_t *loc,
                     dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata_stat path=[%s]", loc->path);
        struct iatt           buf         = {0,};
        int32_t               op_ret      = -1;
        int32_t               op_errno    = 0;
        metadata_private_t  *priv  = NULL;

        //DECLARE_OLD_FS_ID_VAR;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (loc, uncached);

        priv = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

		if(!priv->load_metadata_complete)
			goto uncached;

        //SET_FS_ID (frame->root->uid, frame->root->gid);

        //MAKE_INODE_HANDLE (real_path, this, loc, &buf);

		op_ret = metadata_inode_iatt_get (priv->table, loc, &buf);
        if (op_ret == -1) {
                op_errno = errno;
                gf_log (this->name, (op_errno == ENOENT)?
                        GF_LOG_DEBUG:GF_LOG_ERROR,
                        "lstat on %s failed: %s", loc->path,
                        strerror (op_errno));
                goto uncached;
        }
        op_ret = 0;

        //SET_TO_OLD_FS_ID();
        MTDATA_STACK_UNWIND(stat, frame, op_ret, op_errno, &buf, xdata);

        return 0;

uncached:
		gf_log (this->name, GF_LOG_INFO, "++Goto posix stat uncache op_ret=[%d]!", op_ret);

        STACK_WIND (frame, metadata_stat_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->stat, loc, xdata);
        return 0;
}

int32_t
metadata_lookup (call_frame_t *frame, xlator_t *this, loc_t *loc,
                       dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "00-metadata lookup path=[%s] ,name=[%s], loc->gfid=[%02x%02x], loc->pargfid=[%02x%02x]",   
			loc->path, loc->name,
			loc->gfid[14], loc->gfid[15], 
			loc->pargfid[14], loc->pargfid[15]);
//如果元数据加载标志是完成，则需要查询metadata层缓存，然后返回给上层
//如果元数据加载未完成，则直接发给posix层查询磁盘
        int32_t     				op_ret       = -1;
        int32_t     				op_errno     = 0;
        struct iatt                 stbuf        = {0, };
        struct iatt                 postparent   = {0, };
		int32_t                     gfidless     = 0;
        dict_t                     *xattr_rsp    = NULL;
		fsnode                     *fsnd         = NULL;
		metadata_private_t         *priv         = NULL;
		metadata_local_t           *local        = NULL;

        VALIDATE_OR_GOTO (frame, uncached);
        VALIDATE_OR_GOTO (this, uncached);
        VALIDATE_OR_GOTO (loc, uncached);

		priv  = this->private;
        VALIDATE_OR_GOTO (priv, uncached);

        local = metadata_local_get (frame);
        loc_copy (&local->loc, loc);

		if(!priv->load_metadata_complete)
			goto uncached;

        if (__is_root_gfid (loc->pargfid) &&
            (!loc->name)) {
                gf_log (this->name, GF_LOG_WARNING,
                        "Lookup issued on %s, which is not permitted",
                        GF_HIDDEN_PATH);
                op_errno = EPERM;
                op_ret = -1;
                goto uncached;
        }

        op_ret = dict_get_int32 (xdata, GF_GFIDLESS_LOOKUP, &gfidless);
        
		fsnd = metadata_get_fsnode(priv->table, loc);
		if(!fsnd){
			//gf_log (this->name, GF_LOG_WARNING, "metadata no cache this fsnode loc->path=[%s]", loc->path);
			goto parent;
		}

        op_ret = iatt_from_stat(&stbuf, &fsnd->stat );
       	uuid_copy (stbuf.ia_gfid, fsnd->gfid);

		op_errno = 0;
		//需要从fsnode中的xattr_array中获取每个fsnode的扩展属性 
        if (xdata && (op_ret == 0)) {
            xattr_rsp = metadata_lookup_xattr_get (this, loc,
                                             xdata, &stbuf, fsnd);
        }

parent:
       	op_ret = metadata_parinode_iatt_get (priv->table, loc, &postparent);
       	if (op_ret != 0)
            goto uncached;

        if (!op_ret && !gfidless && uuid_is_null (stbuf.ia_gfid)) {
                gf_log (this->name, GF_LOG_ERROR, "buf->ia_gfid is null for "
                        "%s", (loc->path) ? loc->path: "");
                op_ret = -1;
                //op_errno = ENODATA;
                op_errno = ENOENT;
				//goto uncached;
        }

        if (xattr_rsp)
                dict_ref (xattr_rsp);
		//加载完成
		MTDATA_STACK_UNWIND(lookup, frame, op_ret, op_errno, (loc)?loc->inode:NULL, &stbuf,
                         xattr_rsp, &postparent);
	    if (xattr_rsp)
            dict_unref (xattr_rsp);

		return 0;

uncached:

    	STACK_WIND (frame, metadata_lookup_cbk, FIRST_CHILD(this),
                   FIRST_CHILD(this)->fops->lookup, loc, xdata);

		//dict_foreach (xdata, metadata_xattr_get, NULL);
        return 0;
}

int32_t
metadata_fsetattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
                         struct iatt *stbuf, int32_t valid,
                         dict_t *xdata)
{
gf_log (this->name, GF_LOG_INFO, "++Begin metadata fsetattr valid=[%d] ", valid);
		metadata_local_t *local = NULL;

        local = metadata_local_get (frame);

		local->fd = fd_ref (fd);
		if(xdata)
	        local->xattr = dict_ref (xdata);

        STACK_WIND (frame, metadata_fsetattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->fsetattr, fd, stbuf, valid, xdata);
        return 0;
}

int
metadata_build_child_loc (xlator_t *this, loc_t *child, loc_t *parent, char *name)
{
        if (!child) {
                goto err;
        }

        if (strcmp (parent->path, "/") == 0)
                gf_asprintf ((char **)&child->path, "/%s", name);
        else
                gf_asprintf ((char **)&child->path, "%s/%s", parent->path, name);

        if (!child->path) {
                goto err;
        }

        child->name = strrchr (child->path, '/');
        if (child->name)
                child->name++;

        child->parent = inode_ref (parent->inode);
        child->inode = inode_new (parent->inode->table);

        if (!child->inode) {
                goto err;
        }

        return 0;
err:
        loc_wipe (child);
        return -1;
}
int32_t
metadata_file_layout(xlator_t *this, loc_t *loc, gf_dirent_t *entry, 
				metadata_private_t *priv, fsnode *fsnd, fsedge *fseg)
{
		int                      ret       = -1;
		loc_t                    entry_loc = {0,};
		char                    *linkname  = NULL;
		fsnode                  *newfsnode = NULL;
		fsnode                  *hd_fsnode = NULL;
		fsedge                  *newfsedge = NULL;
		dict_t                  *dict      = NULL;
		int                      hdflag    = 0;
		struct iatt              iatt      = {0,};
		//gf_dirent_t              entries;

        gf_log (this->name, GF_LOG_INFO, "migrate data called on %s", loc->path);

		loc_wipe (&entry_loc);

        ret =metadata_build_child_loc (this, &entry_loc, loc,
                                             entry->d_name);
        if (ret) {
        	gf_log (this->name, GF_LOG_ERROR, "Child loc"
        	" build failed");
        	goto out;
        }

        if (uuid_is_null (entry->d_stat.ia_gfid)) {
        		gf_log (this->name, GF_LOG_ERROR, "%s/%s"
        		"gfid not present", loc->path,
        		entry->d_name);
                //continue;
        }
        entry_loc.inode->ia_type = entry->d_stat.ia_type;

		uuid_copy (entry_loc.gfid, entry->d_stat.ia_gfid);
        uuid_copy (entry_loc.inode->gfid, entry->d_stat.ia_gfid); /* 构建inode的gfid */

        if (uuid_is_null (loc->gfid)) {
        		gf_log (this->name, GF_LOG_ERROR, "%s/%s"
        		"gfid not present", loc->path,
        			entry->d_name);
                //continue;
        }

        uuid_copy (entry_loc.pargfid, loc->gfid);

        if (IA_ISLNK (entry->d_stat.ia_type)){
        	ret = syncop_readlink (this, &entry_loc, &linkname, 
							entry->d_stat.ia_size);
        	if (ret < 0) {
        			gf_log (this->name, GF_LOG_WARNING,
        			"%s: readlink on symlink failed (%s)",
        			entry_loc.path, strerror (errno));
        		goto out;
        	}
        	gf_log (this->name, GF_LOG_ERROR, "This is link file name=[%s],linkname=[%s]", entry->d_name, linkname);
		}

        ret = syncop_lookup (this, &entry_loc, NULL, &iatt,
        						NULL, NULL);
		if (ret) {
            gf_log (this->name, GF_LOG_ERROR, "%s"
           	          " lookup failed", entry_loc.path);
            goto out;
        }

        ret = syncop_getxattr (this, &entry_loc, &dict,
        							NULL);
		if (ret < 0) {
        	gf_log (this->name, GF_LOG_TRACE, "failed to "
                     "get link-to key for %s",
                     	entry_loc.path);
             goto out;
		}

		if(IA_ISREG (entry->d_stat.ia_type) && entry->d_stat.ia_nlink > 1 )
		{
			hd_fsnode = fsnodes_hdlk_node_find(entry, fseg, priv->table, &hdflag);
			if(hdflag == 0)
			{
				//第一个硬链接文件	 hdflag=1
				hdflag = 1;
        		gf_log (this->name, GF_LOG_INFO, "+++++++++first hard link file hdflag=[%d]", hdflag);
				newfsnode = fsnodes_node_create(dict, entry, fseg, fsnd);
				newfsedge = fsedges_edge_create(entry, fsnd, newfsnode,linkname, hdflag);
				add_fsnode_to_hash_table(loc->gfid, newfsnode, newfsedge, priv->table);
			}else
			{
        		gf_log (this->name, GF_LOG_INFO, "Begin create hard link fsdege hdflag=[%d]", hdflag);
				newfsedge = fsedges_edge_create(entry, fsnd, hd_fsnode,linkname, hdflag);
				add_fsnode_to_hash_table(loc->gfid, NULL, newfsedge, priv->table);
			}
		}else{
				newfsnode = fsnodes_node_create(dict, entry, fseg, fsnd );
				newfsedge = fsedges_edge_create(entry, fsnd, newfsnode, linkname, hdflag);
				add_fsnode_to_hash_table(loc->gfid, newfsnode, newfsedge, priv->table);
		}

out:
        loc_wipe (&entry_loc);

        return ret;
}

int32_t
metadata_direct_layout(xlator_t *this, mt_defrag_info_t *defrag, loc_t *loc,
					fsedge *fseg,  fsnode *fsnd)
{
        int                      ret            = -1;
		loc_t                    entry_loc      = {0,};
		fd_t                     *fd            = NULL;
        gf_dirent_t              entries;
        gf_dirent_t             *tmp            = NULL;
        gf_dirent_t             *entry          = NULL;
        gf_boolean_t             free_entries   = _gf_false;
        dict_t                  *mtdata_dict           = NULL;
        off_t                    offset         = 0;
        struct iatt              iatt           = {0,};
        int                      readdirp_errno = 0;
//----------------------->
    	metadata_private_t     *priv = NULL;
		fsnode                 *newfsnode = NULL;
		fsedge                 *newfsedge = NULL;
//----------------------->
		priv = this->private;
    	if (!priv)
       		goto out;

        ret = syncop_lookup (this, loc, NULL, &iatt, NULL, NULL);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Lookup failed on %s",
                        loc->path);
                goto out;
        }		
		
        fd = fd_create (loc->inode, defrag->pid);
        if (!fd) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to create fd");
                ret = -1;
                goto out;
        }

        ret = syncop_opendir (this, loc, fd);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "Failed to open dir %s",
                        loc->path);
                ret = -1;
                goto out;
        }
//gf_log (this->name, GF_LOG_ERROR, "Test for fd fd-value=[%ld] ,path=[%s],name=[%s]", fd->_ctx->value1, loc->path, loc->name);

		INIT_LIST_HEAD (&entries.list);
       	while ((ret = syncop_readdirp (this, fd, 131072, offset, NULL,
                &entries)) != 0)
        {
                if (ret < 0) {
                        gf_log (this->name, GF_LOG_ERROR, "Readdir returned %s"
                                ". Aborting fix-layout",strerror(errno));
                        goto out;
                }

                /* Need to keep track of ENOENT errno, that means, there is no
 *                    need to send more readdirp() */
                readdirp_errno = errno;

                if (list_empty (&entries.list))
                        break;

                free_entries = _gf_true;

                list_for_each_entry_safe(entry, tmp, &entries.list, list) {
                        offset = entry->d_off;

                        if (!strcmp (entry->d_name, ".") ||
                            !strcmp (entry->d_name, ".."))
                                continue;

                        if (!IA_ISDIR (entry->d_stat.ia_type)){
						 	    metadata_file_layout(this,  loc, entry, priv, fsnd, fseg);
                                continue;
						}

                        loc_wipe (&entry_loc);

                        ret =metadata_build_child_loc (this, &entry_loc, loc,
                                                  entry->d_name);
                        if (ret) {
                                gf_log (this->name, GF_LOG_ERROR, "Child loc"
                                        " build failed");
                                goto out;
                        }

                        if (uuid_is_null (entry->d_stat.ia_gfid)) {
                                gf_log (this->name, GF_LOG_ERROR, "%s/%s"
                                        "gfid not present", loc->path,
                                         entry->d_name);
                                continue;
                        }
                        entry_loc.inode->ia_type = entry->d_stat.ia_type;

                        uuid_copy (entry_loc.gfid, entry->d_stat.ia_gfid);
                        uuid_copy (entry_loc.inode->gfid, entry->d_stat.ia_gfid); /* 构建inode的gfid */

                        if (uuid_is_null (loc->gfid)) {
                                gf_log (this->name, GF_LOG_ERROR, "%s/%s"
                                        "gfid not present", loc->path,
                                         entry->d_name);
                                continue;
                        } 

						uuid_copy (entry_loc.pargfid, loc->gfid);

                        ret = syncop_lookup (this, &entry_loc, NULL, &iatt,
                                             NULL, NULL);
                        if (ret) {
                                gf_log (this->name, GF_LOG_ERROR, "%s"
                                        " lookup failed", entry_loc.path);
                                continue;
                        }

        				ret = syncop_getxattr (this, &entry_loc, &mtdata_dict,
        										NULL);
						if (ret < 0) {
				        	gf_log (this->name, GF_LOG_TRACE, "failed to "
                     				"get link-to key for %s", entry_loc.path);
				             goto out;
						}

						newfsnode = fsnodes_node_create(mtdata_dict, entry, fseg, fsnd );
						newfsedge = fsedges_edge_create(entry, fsnd, newfsnode, NULL, 0);
						add_fsnode_to_hash_table(loc->gfid, newfsnode, newfsedge, priv->table);
/* End add */
                        ret = metadata_direct_layout (this, defrag, &entry_loc, 
									newfsedge, newfsnode);

                        if (ret) {
                                gf_log (this->name, GF_LOG_ERROR, "Fix layout "
                                        "failed for %s", entry_loc.path);
                                defrag->total_failures++;
                                goto out;
                        }

                }
                gf_dirent_free (&entries);
                free_entries = _gf_false;
                INIT_LIST_HEAD (&entries.list);
                if (readdirp_errno == ENOENT)
                        break;
        }

        ret = 0;
out:
        if (free_entries)
                gf_dirent_free (&entries);

        loc_wipe (&entry_loc);

        if (mtdata_dict)
                dict_unref(mtdata_dict);

        if (fd)
                fd_unref (fd);  /* 释放文件fd引用 */

        return ret;

}

void 
metadata_build_root_inode(xlator_t *this, inode_t **inode)
{
		inode_table_t         *itable      = NULL;
		uuid_t                root_gfid    = {0,} ;

		itable = inode_table_new(0, this);
		if(!itable)
			return ;

		root_gfid[15] = 1;
		*inode = inode_find(itable, root_gfid);
}

void 
metadata_build_root_loc(inode_t *inode , loc_t  *loc)
{
		loc->path = "/";
		loc->inode = inode;
		loc->inode->ia_type = IA_IFDIR;
		memset (loc->gfid, 0 , 16);
		loc->gfid[15] = 1;
}

int32_t
metadata_layout_start(void *data)
{
		xlator_t              *this        = NULL;
		metadata_private_t    *priv        = NULL;
		mt_defrag_info_t      *defrag      = NULL;
		uint32_t              ret          = -1;
		loc_t                 loc          = {0,};
		struct iatt           iatt         = {0,};
		struct iatt           parent       = {0,};
//--------------------->
		dict_t                *mtdata_dict     = NULL;
		fsnode                *fsndroot        = NULL;
		fsedge                *fsegroot        = NULL;
//<--------------------

		this = data;
		if(!this)
			goto err;
	
		priv = this->private;
		if(!priv)
			goto err;

		defrag = priv->defrag;
		if(!defrag)
			goto err;

		gettimeofday(&defrag->start_time, NULL);
		metadata_build_root_inode(this, &defrag->root_inode);
		if(!defrag->root_inode)
			goto err;

		metadata_build_root_loc(defrag->root_inode, &loc);
		ret = syncop_lookup(this, &loc, NULL, &iatt, NULL, &parent);
		if(ret){
			gf_log(this->name, GF_LOG_ERROR, "look on / failed");
			goto err;
		}

/* 创建 /目录后，添加到fsnode树形结构的根节点 */
        mtdata_dict = dict_new ();
        if (!mtdata_dict) {
                ret = -1;
                goto err;
        }
		ret = syncop_getxattr (this, &loc, &mtdata_dict, NULL);
		if (ret < 0) {
        	gf_log (this->name, GF_LOG_TRACE, "failed to "
            		"get link-to key for %s",
                     loc.path);
        }

		fsndroot = fsnodes_rootnode_create(&loc, &iatt, mtdata_dict);

		add_fsnode_to_hash_table(loc.gfid, fsndroot, fsegroot, priv->table);
/* End add */

        ret = metadata_direct_layout (this, defrag, &loc, fsegroot, 
									fsndroot );

		priv->load_metadata_complete = 1;  /* 加载完成 */
		showFsnodes(priv);
		showFsedges(priv);
		//showRfsedge(priv);
        gf_log (this->name, GF_LOG_ERROR, "metadata layout over ret=[%d]!", ret);

		return ret;
err:
/* 缺少内容 释放内存*/
        if (defrag) {
                GF_FREE (defrag);
                priv->defrag = NULL;
        }

		return ret;
}

int                                                                           
metadata_listener_stop (xlator_t *this)                                             
{                                                                             
        zefs_ctx_t  *ctx = NULL;                                              
        cmd_args_t       *cmd_args = NULL;                                    
        int              ret = 0;                                             
                                                                              
        ctx = this->ctx;                                                      
        GF_ASSERT (ctx);                                                      
        cmd_args = &ctx->cmd_args;                                            
        if (cmd_args->sock_file) {                                            
                ret = unlink (cmd_args->sock_file);                           
                if (ret && (ENOENT == errno)) {                               
                        ret = 0;                                              
                }                                                             
        }                                                                     
                                                                              
        if (ret) {                                                            
                gf_log (this->name, GF_LOG_ERROR, "Failed to unlink listener "
                        "socket %s, error: %s", cmd_args->sock_file,          
                        strerror (errno));                                    
        }                                                                     
        return ret;                                                           
}                                                                             
static int
metadata_layout_done(int ret, call_frame_t *sync_frame, void *data)
{
/* 线程完成扫描磁盘工作后是否关闭 */
		//metadata_listener_stop (sync_frame->this);

		//STACK_DESTROY (sync_frame->root);
		//kill (getpid(), SIGTERM);
		return 0;
}

static void *
load_metadata_thread_proc (void *data)
{
        //metadata_private_t	*priv = data;
	//	priv = priv; 
        //scan all metadata from brick directory from "/" (gfid=0x01) , and construct the  nodehash table...
        int                      ret    = -1;
        call_frame_t            *frame  = NULL;
        metadata_private_t	    *priv   = NULL;
		mt_defrag_info_t        *defrag = NULL;
        xlator_t                *this   = NULL;

		this = data;
		priv = this->private;
		if(!priv)
			goto out;

		defrag = priv->defrag;

		frame = create_frame(this, this->ctx->pool);
		if(!frame)
			goto out;

		frame->root->pid = -4;
		defrag->pid = frame->root->pid;
		//defrag->defrag_status = GF_DEFRAG_STATUS_STARTED;
		
		ret = synctask_new (this->ctx->env, metadata_layout_start,
						metadata_layout_done, frame, this);
		if(ret)
			gf_log (this->name, GF_LOG_ERROR, "Could not create task for rebalance");

out:
        return NULL;
}


int32_t
mem_acct_init (xlator_t *this)
{
    int     ret = -1;

    ret = xlator_mem_acct_init (this, gf_metadata_mt_end + 1);

    return ret;
}

int
notify (xlator_t *this, int event, void *data, ...)
{

		metadata_private_t	    *priv = NULL;
		int ret = -1;
		

		priv = this->private;

		if (!priv)
				return -1;


		switch (event) {
		case GF_EVENT_CHILD_UP:
				if ((!priv->load_metadata_thread) && (priv->load_metadata_complete == 0)) {
                        //ret = pthread_create (&priv->load_metadata_thread, NULL,
                         //                     load_metadata_thread_proc, this->private);
                        ret = pthread_create (&priv->load_metadata_thread, NULL,
                                              load_metadata_thread_proc, this);
                        if (ret != 0) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "pthread_create() failed (%s)",
                                        strerror (errno));
                        }
                }
        		
				break;

		case GF_EVENT_CHILD_DOWN:
				
				break;

		case GF_EVENT_CHILD_CONNECTING:
				
				break;

		default:
				break;
		}

		ret = default_notify (this, event, data);
		
		return ret;

}


int
init (xlator_t *this)
{

    int                 ret = -1;
    metadata_private_t     *priv = NULL;
      
    if (!this->children || this->children->next) {
            gf_log (this->name, GF_LOG_ERROR,
                    "FATAL: metadata not configured with exactly "
                    "one child");
            goto out;
    }
    if (!this->parents) {
        gf_log (this->name, GF_LOG_WARNING,
                "dangling volume. check volfile ");
    }

/* Add by hf@20150320 for meta */
	GF_VALIDATE_OR_GOTO ("metadata", this, out);
	mt_defrag_info_t     *defrag        = NULL;
/* End add */

    priv = GF_CALLOC (1, sizeof (*priv), gf_metadata_mt_private_t);
    if (!priv)
        goto out;
	GF_OPTION_INIT ("total-metadata-mem-limit", priv->total_metadata_mem_limit, size, out);
    //LOCK_INIT(&priv->lock);
/* Add by hf@20150320 for tst */

    defrag = GF_CALLOC (1, sizeof (mt_defrag_info_t),
    		gf_defrag_mt_info_t);

    //defrag->is_exiting = 0;
	defrag->stats = _gf_false;

	priv->load_metadata_complete = 0;  /* 加载未完成 */
	priv->keep_metadata_partially = 0; /* 需要从磁盘上找 */
	priv->defrag = defrag;
/* End add */
    pthread_mutex_init (&priv->mutex, 0);

/* Add by hf@20150508 for priv->table */
	priv->table = metadata_node_table_new();
	if(!priv->table){
		gf_log(this->name, GF_LOG_ERROR, "Init metadata_node_table falied !");
		goto out;
	}
	priv->table->virfd_num = 4;   //20150601
/* End add */
	LOCK_INIT(&priv->table->lock);

    this->private = priv;

    ret = 0;
out:
    if (ret) {
        if (priv) {
			GF_FREE (priv->defrag);
            GF_FREE (priv);
        }	
        this->private = NULL;
    }
    return ret;
}

void
fini (xlator_t *this)
{
    metadata_private_t     *priv = NULL;

    priv = this->private;
    if (!priv)
        goto out;
    this->private = NULL;
	//release priv->nodehash[] here....
	
	//LOCK_DESTROY (&priv->lock);
    pthread_mutex_destroy (&priv->mutex);
	LOCK_DESTROY (&priv->table->lock);
    GF_FREE (priv);
out:
    return;
}


struct xlator_fops fops = {
		.lookup      = metadata_lookup,
        .stat        = metadata_stat,
        .opendir     = metadata_opendir,
        .readdir     = metadata_readdir,
        .readdirp    = metadata_readdirp,
        .readlink    = metadata_readlink,
        .mknod       = metadata_mknod,
        .mkdir       = metadata_mkdir,
        .unlink      = metadata_unlink,
        .rmdir       = metadata_rmdir,
        .symlink     = metadata_symlink,
        .rename      = metadata_rename,
        .link        = metadata_link,
        .truncate    = metadata_truncate,
        .create      = metadata_create,
        .open        = metadata_open,
        .readv       = metadata_readv,
        .writev      = metadata_writev,
        .statfs      = metadata_statfs,
        .flush       = metadata_flush,
        .fsync       = metadata_fsync,
        .setxattr    = metadata_setxattr,
        .fsetxattr   = metadata_fsetxattr,
        .getxattr    = metadata_getxattr,
        .fgetxattr   = metadata_fgetxattr,
        .removexattr = metadata_removexattr,
        .fremovexattr = metadata_fremovexattr,
        .fsyncdir    = metadata_fsyncdir,
        .access      = metadata_access,
        .ftruncate   = metadata_ftruncate,
        .fstat       = metadata_fstat,
        .lk          = metadata_lk,
        .inodelk     = metadata_inodelk,
        .finodelk    = metadata_finodelk,
        .entrylk     = metadata_entrylk,
        .fentrylk    = metadata_fentrylk,
        .rchecksum   = metadata_rchecksum,
        .xattrop     = metadata_xattrop,
        .fxattrop    = metadata_fxattrop,
        .setattr     = metadata_setattr,
        .fsetattr    = metadata_fsetattr,

};

struct xlator_dumpops dumpops;

struct xlator_cbks cbks = {
//add by hf 2015-06-01-->
		.releasedir  = metadata_releasedir,             //Add by hf@20150601 for releasedir
		.release  = metadata_release,             //Add by hf@20150601 for release
//end by hf 2015-06-01-->
};

struct volume_options options[] = {
    { .key  = {"total-metadata-mem-limit" },
      .type = GF_OPTION_TYPE_SIZET,
      .min  = 512 * GF_UNIT_MB,
      .max  = 8 * GF_UNIT_GB,
      .default_value = "2GB",
      .description = "the threshold for loading all metadata in memory , if more than this , keep metadata partially in memory",
    },
    { .key  = {NULL} },
};
//#endif
