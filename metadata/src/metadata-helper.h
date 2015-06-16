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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include "xlator.h"
#include "metadata.h"

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
int fsnode_xattr_del(char *key, fsnode *fsnd);
uint32_t fsnode_xattr_upd (xlator_t *this, loc_t *loc, dict_t *xattr_req, fsnode* fsnd);

#endif
