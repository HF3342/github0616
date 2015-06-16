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
//#include "options.h"
//#include "zefs3-xdr.h"

inline fsnode *fsnode_new (){
	fsnode * p = NULL;

	p = GF_CALLOC (1, sizeof(*p),gf_metadata_mt_fsnode_t);

	return p;
}

inline void fsnode_destroy (fsnode *p){
	if (p == NULL) {
		return;
	}
	GF_FREE (p);
	p = NULL;
	return;
}

inline fsedge *fsedge_new (const char *name, const char *lkname){
	fsedge * p = NULL;
	p = GF_CALLOC (1, sizeof(*p),gf_metadata_mt_fsedge_t);
	if(!p)
		goto out;

	if(name)
		p->name = GF_CALLOC (1, strlen(name)+1, gf_metadata_mt_char);
	
	if(lkname)
		p->linkname = GF_CALLOC (1, strlen(lkname)+1, gf_metadata_mt_char);

out:
	return p;
}

inline void fsedge_destroy (fsedge *p){
	if (p == NULL) {
		return;
	}
	if(p->name){
		GF_FREE (p->name);
		p->name = NULL;
	}
	if(p->linkname){
		GF_FREE (p->linkname);
		p->linkname = NULL;
	}

	p->child = NULL;
	p->parent = NULL;

	GF_FREE (p);
	p = NULL;
	return;
}

/* Add by hf@20150514 for xattr */
inline xattr *xattr_new(){
	struct _xattr   *xa = NULL;

	xa = GF_CALLOC(1, sizeof(*xa), gf_metadata_mt_fsnode_t);
	xa->key = NULL;
	xa->value = NULL;
	xa->vallen = 0;
	
	return xa;
}

inline void xattr_destroy(fsnode *fsnd , xattr *xa){
	if(fsnd == NULL || xa == NULL)
		return ;

	if(xa->key){
		GF_FREE(xa->key);
		xa->key = NULL;
	}
	if(xa->value){
		GF_FREE(xa->value);	
		xa->value = NULL;
	}
	fsnd->xattr_cnt-- ;
	GF_FREE(xa);
	xa = NULL;
	return;
}
/* End add */
void _remove_fsnode_from_hash_table(fsnode *p, metadata_node_table_t *table) {

}

void remove_fsnode_from_hash_table(fsnode *p, metadata_node_table_t *table) {

}

/* For find hard link */
fsnode *fsnodes_hdlk_node_find(gf_dirent_t  *entry, fsedge *pfseg, metadata_node_table_t *table, int *flag)
{
	uint32_t     nodepos = 0;
	uint32_t     fg      = 0;
	fsnode      *fsnd    = NULL;
	fsnode      *tmpfsnd    = NULL;

	nodepos = NODEHASHPOS(entry->d_stat.ia_gfid);

	if (list_empty (&table->fsnodes_list[nodepos]))
   		goto out;
//硬链接gfid是一样的

	list_for_each_entry_safe(fsnd, tmpfsnd, &table->fsnodes_list[nodepos], fsnd_list){
		if(fsnd){
			if(IA_ISREG(ia_type_from_st_mode (fsnd->stat.st_mode)) &&
				(fsnd->stat.st_ino == entry->d_stat.ia_ino))
				//gf_log("Testlog", GF_LOG_ERROR, "<------i=[%d],next->name=[%s] ino=[%ld]", nodepos,fsnd->parents->name, entry->d_stat.ia_ino);
				fg = 1;
				goto out;
		}
	}

out:
	*flag = fg;
	return fsnd ;
}

static char* metadata_ignore_xattrs[] = {
        "gfid-req",
        ZEFS_ENTRYLK_COUNT,
        ZEFS_INODELK_COUNT,
        ZEFS_POSIXLK_COUNT,
        NULL
};

int 
fsnode_xattr_set(dict_t *dict,  fsnode *fsnd ){
        if (!dict) {                                                                               
                gf_log_callingfn ("dict", GF_LOG_WARNING,                                          
                                  "dict is NULL");                                                 
                return -1;                                                                         
        }                                                                                          
		int           i        = 0;
		int32_t       vallen   = 0;
        data_pair_t *pairs     = NULL;
        //data_pair_t *next  = NULL;
		struct _xattr *fsnd_xattr = NULL;

        pairs = dict->members_list;                                                                

        while (pairs) {
				fsnd_xattr = xattr_new();
				//INIT_LIST_HEAD(&fsnd_xattr->attr_list);
				vallen = pairs->value->len;

				fsnd_xattr->key = GF_CALLOC (1, strlen(pairs->key)+1, gf_metadata_mt_char);
				fsnd_xattr->value = GF_CALLOC (1, vallen+1, gf_metadata_mt_char);

				strcpy(fsnd_xattr->key, pairs->key);
				fsnd_xattr->vallen = vallen;
				memcpy(fsnd_xattr->value, pairs->value->data, vallen);

				list_add(&fsnd_xattr->attr_list, &fsnd->xattr_head);

				i++;
/*
gf_log("Testlog", GF_LOG_ERROR, "key=[%s], vallen=[%d], value=[%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x] i=[%d]", 
					fsnd_xattr->key, vallen,
					fsnd_xattr->value[0], fsnd_xattr->value[1], fsnd_xattr->value[2], fsnd_xattr->value[3],
					fsnd_xattr->value[4], fsnd_xattr->value[5], fsnd_xattr->value[6], fsnd_xattr->value[7],
					fsnd_xattr->value[8], fsnd_xattr->value[9], fsnd_xattr->value[10], fsnd_xattr->value[11],
					fsnd_xattr->value[12], fsnd_xattr->value[13],
					fsnd_xattr->value[14], fsnd_xattr->value[15],i ); 
*/
                pairs = pairs->next;                                                                
		}
		fsnd->xattr_cnt  = i ;

	return 0;
}

/* Emd add */


metadata_node_table_t *metadata_node_table_new()
{
    uint32_t                   i   = 0;
    uint32_t                   ret = -1;
	metadata_node_table_t      *node_table = NULL;

    node_table = GF_CALLOC(1, sizeof(*node_table), gf_metadata_mt_table_t);
	if(!node_table)
		goto out;

    node_table->hashsize=NODEHASHSIZE; 

    node_table->fsnodes_list=(void *)GF_CALLOC (NODEHASHSIZE, sizeof (struct list_head),gf_metadata_mt_fsnode_t);
	if(!node_table->fsnodes_list)
		goto out;

    for(i=0;i<node_table->hashsize;i++)
    {
        INIT_LIST_HEAD(&node_table->fsnodes_list[i]);
    }

    node_table->fsedges_list=(void *)GF_CALLOC (NODEHASHSIZE, sizeof (struct list_head),gf_metadata_mt_fsedge_t);
	if(!node_table->fsedges_list)
		goto out;

    for(i=0;i<node_table->hashsize;i++)
    {
        INIT_LIST_HEAD(&node_table->fsedges_list[i]);
    }

    node_table->nodes=0;
    node_table->dirnodes=0;
    node_table->filenodes=0;
    node_table->total_metadata_mem=0;

	ret = 0;
out:
	return node_table;
}

void _add_fsnode_to_hash_table(uuid_t gfid , fsnode *p, fsedge *eg, metadata_node_table_t *table) {
	uint32_t nodepos = 0;

	if (p == NULL && eg == NULL)
		return;

//硬链接时，只需要新增一个fsedge 
	if (p == NULL && eg != NULL)
		goto onlyeg;

	//p->parents = eg;    /* 指向fsedge */ /* del by hf@20150529 for test*/
	nodepos = NODEHASHPOS(p->gfid);

	list_add(&p->fsnd_list, &table->fsnodes_list[nodepos]);
	
	table->nodes++;
	if (S_ISDIR (p->stat.st_mode)) {
		table->dirnodes++;
	} else {
		table->filenodes++;
	}

onlyeg:

	if(!eg)  //for root fsedge
		goto out;

	nodepos = EDGEHASHPOS(eg->name, gfid);
	list_add(&eg->fseg_list, &table->fsedges_list[nodepos]);

	list_add(&eg->child_list, &eg->parent->children);
	list_add(&eg->parent_list, &eg->child->parents);   //20150530
	
out:
	return;
}

void add_fsnode_to_hash_table(uuid_t gfid, fsnode *p, fsedge *eg, metadata_node_table_t *table) {

        //if (!p || !table) {
        if ((!p && !eg) || !table) {
                return;
        }

        LOCK (&table->lock);
        {
               _add_fsnode_to_hash_table(gfid, p, eg, table);
        }
        UNLOCK (&table->lock);
        return;
}

/* Note:    Add by HF@20150507
 * Decribe: 创建根目录的fsnode 
 */
fsnode *fsnodes_rootnode_create(loc_t *loc, struct iatt *iatt, dict_t *dict)
{
    fsnode        *new_fsnd = NULL;
    new_fsnd = fsnode_new();
	if(!new_fsnd)
		goto out;

    uuid_copy(new_fsnd->gfid, loc->gfid);
    new_fsnd->xattr_cnt = 0;

	LOCK_INIT(&new_fsnd->lock);
	LOCK(&new_fsnd->lock);
	{
		iatt_to_stat(iatt, &new_fsnd->stat);
	}
	UNLOCK(&new_fsnd->lock);

    INIT_LIST_HEAD(&new_fsnd->xattr_head);
    INIT_LIST_HEAD(&new_fsnd->children);
	INIT_LIST_HEAD(&new_fsnd->parents);


    fsnode_xattr_set(dict, new_fsnd);

out:
    return new_fsnd;
}

fsnode *fsnodes_node_create(dict_t *dict,  gf_dirent_t  *entry ,fsedge *fseg, fsnode *fsnd)
{
    fsnode        *new_fsnd = NULL;
    new_fsnd = fsnode_new();
	if(!new_fsnd)
		goto out;

    INIT_LIST_HEAD(&new_fsnd->xattr_head);
    INIT_LIST_HEAD(&new_fsnd->children);
	INIT_LIST_HEAD(&new_fsnd->parents);

	LOCK_INIT(&new_fsnd->lock);

    uuid_copy(new_fsnd->gfid, entry->d_stat.ia_gfid);
	LOCK(&fsnd->lock);
	{
    	iatt_to_stat(&entry->d_stat, &new_fsnd->stat);
	}
	UNLOCK(&fsnd->lock);

    new_fsnd->xattr_cnt = 0;
    fsnode_xattr_set(dict, new_fsnd);

/* 20150529
    new_fsnd->children = NULL;
    new_fsnd->parents = NULL;
*/

out:
    return new_fsnd;
}

fsedge *fsedges_edge_create(gf_dirent_t  *entry,
		fsnode *par_fsnd, fsnode *nxt_fsnd, const char *lkname, int hdflag)
{

    fsedge         *new_fseg = NULL;
    //fsedge         *hard_fseg = NULL;

    new_fseg = fsedge_new(entry->d_name, lkname);
	if(!new_fseg)
		goto out;

    strcpy(new_fseg->name, entry->d_name);
    new_fseg->nleng = strlen(entry->d_name);
    new_fseg->child = nxt_fsnd;
    new_fseg->parent =  par_fsnd;

	//每个目录下的第一个fsedge节点
/* Add 20150417 */
    new_fseg->d_ino = entry->d_ino;
    new_fseg->d_off = entry->d_off;
    new_fseg->d_len = entry->d_len;
    new_fseg->d_type = entry->d_type;
    new_fseg->d_sync = entry->d_sync;
/* End add */

	//for hard link 
    /* 20150530
	if (IA_ISREG (ia_type_from_st_mode (nxt_fsnd->stat.st_mode)) && hdflag){ 
		gf_log("Testlog", GF_LOG_ERROR, "fsnode hard link d_name=[%s]", 
					entry->d_name);
	    list_add(&new_fseg->parent_list, nxt_fsnd->parents);  
	}
    */

	if (IA_ISLNK (entry->d_stat.ia_type) && lkname){
		strcpy(new_fseg->linkname, lkname);
		gf_log("Testlog", GF_LOG_ERROR, "fsnode link name =[%s]", new_fseg->linkname);
	}


	gf_log("Testlog", GF_LOG_ERROR, "1------------------fsedge->name=[%s]----", new_fseg->name);

out:
    return new_fseg;
}


void 
showFsnodes(metadata_private_t  *priv)
{
	uint32_t   i    = 0 ;
	fsnode    *fsnd = NULL;
	fsnode    *tmpfsnd = NULL;
	xattr     *xtr = NULL;
gf_log("Testlog", GF_LOG_ERROR, "<------------------------------------Begin show fsnode---------------------------------->");

gf_log("Testlog", GF_LOG_ERROR, "<--------priv->nodes=[%d]", priv->table->nodes);
gf_log("Testlog", GF_LOG_ERROR, "<--------priv->dirnodes=[%d]", priv->table->dirnodes);
gf_log("Testlog", GF_LOG_ERROR, "<--------priv->filenodes=[%d]", priv->table->filenodes);
//gf_log("Testlog", GF_LOG_ERROR, "<--------priv->total_metadata_mem=[%ld]", priv->table->total_metadata_mem);
	for (i = 0; i < NODEHASHSIZE; i++)
	{

		if(list_empty(&priv->table->fsnodes_list[i]))
			continue;

		list_for_each_entry_safe(fsnd, tmpfsnd, &priv->table->fsnodes_list[i], fsnd_list){
			if(!__is_root_gfid (fsnd->gfid))
/* 20150529 
			gf_log("Testlog", GF_LOG_ERROR, "<------i=[%d],-fsedge->name=[%s] fsnode->gfid=[%s]", 
				i,fsnd->parents->name, uuid_utoa(fsnd->gfid));
*/
			gf_log("Testlog", GF_LOG_ERROR, "<------i=[%d],fsnode->gfid=[%s]", 
				i,uuid_utoa(fsnd->gfid));
/* add for xattr */
			list_for_each_entry(xtr,  &fsnd->xattr_head, attr_list){
				gf_log("Testlog", GF_LOG_ERROR, ">>>>>>>key=[%s] value=[%02x%02x]", 
					xtr->key, xtr->value[2],xtr->value[3]);
			}
/* End add */
		}
	}

gf_log("Testlog", GF_LOG_ERROR, "<------------------------------------End  ----------------------------------->");
}

void 
showFsedges(metadata_private_t  *priv)
{
	uint32_t   i    = 0 ;
	fsedge    *fseg = NULL;
#if 0
20150526
	fsedge    *hard_fseg = NULL;
#endif

	for (i = 0; i < NODEHASHSIZE; i++)
	{

		if(list_empty(&priv->table->fsedges_list[i]))
			continue;

		list_for_each_entry(fseg, &priv->table->fsedges_list[i], fseg_list){
            gf_log("Testlog", GF_LOG_ERROR, "<------i=[%d],-fsedge->name=[%s],linkname=[%s] parent->gfid=[%02x%02x], child->gfid=[%02x%02x] ", 
						i,fseg->name, fseg->linkname, fseg->parent->gfid[14], fseg->parent->gfid[15],
							fseg->child->gfid[14], fseg->child->gfid[15]);
				//for hard link 
		}
	}

}


fsnode *
get_next_fsnode(metadata_node_table_t * table, uuid_t  gfid)
{
        uint32_t   posnode = 0;
        posnode = NODEHASHPOS(gfid);

        fsnode  *fsnd = NULL;

        if (list_empty (&table->fsnodes_list[posnode]))
            goto out;

        list_for_each_entry(fsnd,  &table->fsnodes_list[posnode], fsnd_list){
            if (!uuid_compare (fsnd->gfid, gfid)) {
                goto out;
            }
        }
		fsnd = NULL;
out:
        return fsnd;
}

fsedge *
get_next_fsedge(metadata_node_table_t * table, uuid_t  gfid, const char *name )
{
        uint32_t   posnode = 0;
        posnode = EDGEHASHPOS((char*)name,gfid);

        fsedge  *fseg = NULL;
        fsedge  *tmp_fseg = NULL;
        fsnode  *fsnd = NULL;

        if (list_empty (&table->fsedges_list[posnode]))
            goto out;

		fsnd = get_next_fsnode(table, gfid);
		if(!fsnd || list_empty(&fsnd->children))
			goto out;

        list_for_each_entry_safe(fseg, tmp_fseg,  &fsnd->children,  child_list){
            if(!strcmp(name, fseg->name)){
				goto out;
            }
        }
		fseg = NULL;
out:
        return fseg;
}

fsnode *
fsnodes_node_add(dict_t *dict, struct iatt  *d_stat)
{
    fsnode        *new_fsnd = NULL;
    new_fsnd = fsnode_new();
	if(!new_fsnd)
		goto out;

    uuid_copy(new_fsnd->gfid, d_stat->ia_gfid);

	LOCK_INIT(&new_fsnd->lock);
	LOCK(&new_fsnd->lock);
	{
    	iatt_to_stat(d_stat,&new_fsnd->stat);
	}
	UNLOCK(&new_fsnd->lock);

    new_fsnd->xattr_cnt = 0;

    INIT_LIST_HEAD(&new_fsnd->xattr_head);
    INIT_LIST_HEAD(&new_fsnd->children);
	INIT_LIST_HEAD(&new_fsnd->parents);


    fsnode_xattr_set(dict, new_fsnd);

out:
    return new_fsnd;
}

fsedge *
fsedges_edge_add(struct dirent *entry, 
		fsnode *par_fsnd, fsnode *nxt_fsnd, const char *lkname)
{

    fsedge         *new_fseg = NULL;

    new_fseg = fsedge_new(entry->d_name, lkname);
	if(!new_fseg)
		goto out;

    strcpy(new_fseg->name, entry->d_name);
    new_fseg->nleng = strlen(entry->d_name);
    new_fseg->child = nxt_fsnd;
    new_fseg->parent =  par_fsnd;
	//每个目录下的第一个fsedge节点
    new_fseg->d_ino = entry->d_ino;
    new_fseg->d_off = entry->d_off;
    new_fseg->d_len = entry->d_reclen;
    new_fseg->d_type = entry->d_type;
    //new_fsnd->d_sync = entry->d_sync;
    
	//for hard link  refer dht-rebalance.c:215
    /* 20150530
	if (IA_ISREG (entry->d_type) &&
			lkname ){ 
		gf_log("Testlog", GF_LOG_ERROR, "fsnode hard link first_fseg name=[%s]", 
					entry->d_name);
		list_add(&new_fseg->parent_list, nxt_fsnd->parents);
	}
    */

	// for symlink
	if (IA_ISLNK (entry->d_type) && lkname){
		strcpy(new_fseg->linkname, lkname);
		gf_log("Testlog", GF_LOG_ERROR, "fsnode symlink name =[%s], d_name=[%s]", new_fseg->linkname, entry->d_name);
	}
	
	gf_log("Testlog", GF_LOG_ERROR, "1------------------fsedge->name=[%s]----", new_fseg->name);

out:
    return new_fseg;
}

void 
fsnodes_xattr_del(fsnode *fsnd)
{
	xattr       *fsnd_xtr = NULL;
	xattr       *tmp_xtr = NULL;

    if (list_empty (&fsnd->xattr_head))
        goto out;

	list_for_each_entry_safe(fsnd_xtr,  tmp_xtr, &fsnd->xattr_head,  attr_list){
		if(fsnd_xtr){
/*
            gf_log("Testlog", GF_LOG_ERROR, "del xattr from fsnode where key=[%s]  gfid=[%02x%02x]",
            		fsnd_xtr->key, fsnd->gfid[14], fsnd->gfid[15]);
*/
			list_del(&fsnd_xtr->attr_list);
    		xattr_destroy(fsnd, fsnd_xtr);
			fsnd_xtr = NULL;
		}
	}
out:
	return;
}

void 
fsnodes_node_del(metadata_node_table_t *table, uuid_t  gfid, ia_type_t ia_type)
{
    uint32_t     nodepos  = 0;
    fsnode      *fsnd     = NULL;
    fsnode      *tmpfsnd  = NULL;

    nodepos = NODEHASHPOS(gfid);

    if (list_empty (&table->fsnodes_list[nodepos]))
        goto out;

    list_for_each_entry_safe(fsnd, tmpfsnd, &table->fsnodes_list[nodepos], fsnd_list){
        if(fsnd){
            if(!uuid_compare (fsnd->gfid, gfid)){
/*&
                gf_log ("Testlog", GF_LOG_ERROR, "delete from fsnode where i=[%d],gfid=[%02x%02x]",
                        nodepos,fsnd->gfid[14], fsnd->gfid[15]);
*/
                list_del(&fsnd->fsnd_list);
				fsnodes_xattr_del(fsnd);
                fsnode_destroy(fsnd);
				fsnd = NULL;
                break;

            }
        }
    }

    table->nodes--;
    if (S_ISDIR (ia_type)) {
        table->dirnodes--;
    } else {
        table->filenodes--;
    }
out:
    return ;
}

void fsnodes_node_destory(metadata_node_table_t *table, fsnode *fsnd, ia_type_t ia_type){

gf_log ("Testlog", GF_LOG_ERROR, "delete from fsnode where gfid=[%02x%02x]", fsnd->gfid[14], fsnd->gfid[15]);
    list_del(&fsnd->fsnd_list);
	fsnodes_xattr_del(fsnd);
    fsnode_destroy(fsnd);
	fsnd = NULL;

    table->nodes--;
    if (S_ISDIR (ia_type)) {
        table->dirnodes--;
    } else {
        table->filenodes--;
    }

    return ;
}

void 
fsnodes_edge_destory(fsedge *fseg, const char *name)
{
gf_log ("Testlog", GF_LOG_ERROR, "delete from fsedge where fseg->name=[%s], gfid=[%02x%02x]",
                        fseg->name, fseg->child->gfid[14], fseg->child->gfid[15]);
                list_del(&fseg->child_list);
                list_del(&fseg->fseg_list);
                list_del(&fseg->parent_list);
                fsedge_destroy(fseg);
				fseg = NULL;
    return;
}

void 
fsnodes_edge_del(metadata_node_table_t *table, uuid_t  gfid, const char *name)
{
    uint32_t     nodepos = 0;
    fsedge      *fseg    = NULL;
    fsnode      *parfsnd    = NULL;
    fsedge      *tmpfseg    = NULL;

    nodepos = EDGEHASHPOS((char *)name,gfid);

//判断横向链表是否为空
    if (list_empty (&table->fsedges_list[nodepos]))
        goto out;

	parfsnd = get_next_fsnode(table, gfid);
	if(!parfsnd || list_empty(&parfsnd->children))
		goto out;

    list_for_each_entry_safe(fseg, tmpfseg, &parfsnd->children, child_list){
        if(fseg){
            if(!strcmp(fseg->name, name)){
                gf_log ("Testlog", GF_LOG_ERROR, "delete from fsedge where i=[%d],fseg->name=[%s], gfid=[%02x%02x]",
                        nodepos,fseg->name, fseg->child->gfid[14], fseg->child->gfid[15]);
                list_del(&fseg->child_list);
                list_del(&fseg->fseg_list);
                list_del(&fseg->parent_list);
                fsedge_destroy(fseg);
				fseg = NULL;
                break;
            }
        }

    }

out:
    return;
}

void 
fsnodes_node_upd(fsnode *fsnd , struct iatt  *d_stat, int hdflag)
{
#if 0
	fsedge  *hard_fseg = NULL;
	fsedge  *tmp_fseg = NULL;

	if(fsnd->parents && hdflag){
		list_for_each_entry_safe(hard_fseg,  tmp_fseg, fsnd->parents->parent_list,  parent_list){
    		iatt_to_stat(d_stat,&fsnd->stat);
			gf_log("Testlog", GF_LOG_ERROR, "fsnode hard link name=[%s] updated ", hard_fseg->name);
		}
	}else{
#endif
		LOCK(&fsnd->lock);
		{
    		iatt_to_stat(d_stat,&fsnd->stat);
		}
		UNLOCK(&fsnd->lock);
//	}
//缺少扩展属性更新
//	fsnd->xattr_cnt = 0;

}

void
fsnode_node_edge_destory(fsnode *fsnd){
	fsedge    *tmpfseg = NULL;
    tmpfseg = list_entry(fsnd->parents.next, struct _fsedge, parent_list);
    if(tmpfseg){
    	list_del(&tmpfseg->child_list);
    	list_del(&tmpfseg->fseg_list);
    	list_del(&tmpfseg->parent_list);
    	fsedge_destroy(tmpfseg);
		tmpfseg = NULL;
    }
    list_del(&fsnd->fsnd_list);
    fsnodes_xattr_del(fsnd);
    fsnode_destroy(fsnd);
	fsnd = NULL;

	return;
}

int
fsnode_xattr_del_forupd (char *key, fsnode * fsnd)
{
        int                      ret        = 0;
		xattr                   *fsnd_xattr = NULL;
		xattr                   *tmp_xtr    = NULL;

    	if (list_empty (&fsnd->xattr_head))
        	goto set;

		list_for_each_entry_safe(fsnd_xattr,  tmp_xtr, &fsnd->xattr_head,  attr_list){
			if(!strcmp(fsnd_xattr->key, key)){
            	gf_log("Testlog", GF_LOG_ERROR, "del xattr from fsnode where key=[%s] value=[%02x%02x], gfid=[%02x%02x]",
            			fsnd_xattr->key, fsnd_xattr->value[2], fsnd_xattr->value[3], fsnd->gfid[14], fsnd->gfid[15]);
				list_del(&fsnd_xattr->attr_list);
            	xattr_destroy(fsnd, fsnd_xattr);
				goto set;
			}
		}
		fsnd_xattr = NULL;
set:
	return ret;
}

static int
_fsnode_xattr_update (dict_t *xattr_req,
                      char *key,
                      data_t *data,
                      void *xattrargs)
{
        metadata_xattr_filler_t *filler     = xattrargs;
        //char                    *value      = NULL;
        //ssize_t                  xattr_size = -1;
        int                      ret        = 0;
		xattr                   *fsnd_xattr = NULL;
		int32_t                  vallen     = 0;

    	if (list_empty (&filler->fsnd->xattr_head))
        	goto set;

		ret = fsnode_xattr_del_forupd(key, filler->fsnd);
set:
		fsnd_xattr = xattr_new();
		vallen = data->len;

		fsnd_xattr->key = GF_CALLOC (1, strlen(key)+1, gf_metadata_mt_char);
		if(!fsnd_xattr->key)
			goto out;
		fsnd_xattr->value = GF_CALLOC (1, vallen+1, gf_metadata_mt_char);
		if(!fsnd_xattr->value)
			goto out;

		strcpy(fsnd_xattr->key, key);
		fsnd_xattr->vallen = vallen;
		memcpy(fsnd_xattr->value, data->data, vallen);

		list_add(&fsnd_xattr->attr_list, &filler->fsnd->xattr_head);

		filler->fsnd->xattr_cnt++ ;
/*
gf_log("Testlog", GF_LOG_ERROR, "key=[%s], vallen=[%d], value=[%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x]", 
					fsnd_xattr->key, vallen,
					fsnd_xattr->value[0], fsnd_xattr->value[1], fsnd_xattr->value[2], fsnd_xattr->value[3],
					fsnd_xattr->value[4], fsnd_xattr->value[5], fsnd_xattr->value[6], fsnd_xattr->value[7],
					fsnd_xattr->value[8], fsnd_xattr->value[9], fsnd_xattr->value[10], fsnd_xattr->value[11],
					fsnd_xattr->value[12], fsnd_xattr->value[13],
					fsnd_xattr->value[14], fsnd_xattr->value[15]); 
*/

out:
		return ret;
}

uint32_t 
fsnode_xattr_upd (xlator_t *this, loc_t *loc,
                         dict_t *xattr_req, fsnode *fsnd)
{
        dict_t                      *xattr    = NULL;
        metadata_xattr_filler_t      filler   = {0, };
		int ret     = 0;

        filler.this      = this;
        filler.xattr     = xattr;
        //filler.loc       = loc;
        filler.fsnd      = fsnd;

        ret = dict_foreach (xattr_req, _fsnode_xattr_update, &filler);

        return ret;
}

int32_t
fsnode_setxattr(fsnode *fsnd, const char *name, void *value,
               size_t size, int flags){
        int                      ret        = 0;
		xattr                   *fsnd_xattr = NULL;

    	if (list_empty (&fsnd->xattr_head))
        	goto set;

		ret = fsnode_xattr_del_forupd((char*)name, fsnd);
set:
		fsnd_xattr = xattr_new();

		fsnd_xattr->key = GF_CALLOC (1, strlen(name)+1, gf_metadata_mt_char);
		if(!fsnd_xattr->key)
			goto out;

		fsnd_xattr->value = GF_CALLOC (1, size+1, gf_metadata_mt_char);
		if(!fsnd_xattr->value)
			goto out;

		strcpy(fsnd_xattr->key, name);
		fsnd_xattr->vallen = size;
		memcpy(fsnd_xattr->value, (char*)value, size);

		list_add(&fsnd_xattr->attr_list, &fsnd->xattr_head);

		fsnd->xattr_cnt++ ;
gf_log("Testlog", GF_LOG_ERROR, "key=[%s], vallen=[%ld], value=[%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x]", 
					fsnd_xattr->key, size,
					fsnd_xattr->value[0], fsnd_xattr->value[1], fsnd_xattr->value[2], fsnd_xattr->value[3],
					fsnd_xattr->value[4], fsnd_xattr->value[5], fsnd_xattr->value[6], fsnd_xattr->value[7],
					fsnd_xattr->value[8], fsnd_xattr->value[9], fsnd_xattr->value[10], fsnd_xattr->value[11],
					fsnd_xattr->value[12], fsnd_xattr->value[13],
					fsnd_xattr->value[14], fsnd_xattr->value[15]); 

out:
		return ret;

}

fsnode *
metadata_get_fsnode(metadata_node_table_t *table, loc_t *loc){

        fsnode           *fsnd = NULL;
        fsedge           *fseg = NULL;
//可能存在问题，有待优化

		if(uuid_is_null(loc->pargfid)){
			if(uuid_is_null(loc->gfid)){
				gf_log ("", GF_LOG_ERROR, 
                        "null gfid for path %s", loc->path);  
				goto out;
			}else {
				//直接根据gfid找缓存中对应的fsnode  
            	fsnd = get_next_fsnode(table,loc->gfid);
            	if(!fsnd)
					goto out;
			}
		}else{
			if(!loc->name){
                gf_log ("" , GF_LOG_ERROR,  
                        "null pargfid/name for path %s", loc->path);
				goto out;
        	}else {
				//如果loc->pargfid为空，则需要根据 pargfid+name到缓存中找 
            	fseg = get_next_fsedge(table,loc->pargfid, loc->name);
            	if(fseg && fseg->child){
                	fsnd = fseg->child;
				}
			}
		}
out:
    return fsnd;
}

static gf_boolean_t
metadata_xattr_ignorable (char *key, metadata_xattr_filler_t *filler)
{
        int          i = 0;
        gf_boolean_t ignore = _gf_false;

        GF_ASSERT (key);
        if (!key)
                goto out;
        for (i = 0; metadata_ignore_xattrs[i]; i++) {
                if (!strcmp (key, metadata_ignore_xattrs[i])) {
                        ignore = _gf_true;
                        goto out;
                }
        }
        if ((!strcmp (key, GF_CONTENT_KEY))
            && (!IA_ISREG (filler->stbuf->ia_type)))
                ignore = _gf_true;
out:
        return ignore;
}

static int
_metadata_xattr_get_set (dict_t *xattr_req,
                      char *key,
                      data_t *data,
                      void *xattrargs)
{
        metadata_xattr_filler_t *filler = xattrargs;
        char     *value                 = NULL;
        ssize_t   xattr_size            = -1;
        int       ret                   = -1;
        char     *databuf               = NULL;
        loc_t    *loc                   = NULL;
        ssize_t  req_size               = 0;

//gf_log (filler->this->name, GF_LOG_ERROR, "Test by hf@20150515 key=[%s]", key);

        if (metadata_xattr_ignorable (key, filler))
                goto out;
        /* should size be put into the data_t ? */
        if (!strcmp (key, GF_CONTENT_KEY)
            && IA_ISREG (filler->stbuf->ia_type)) {
#if DEBUG
有待给databuf赋值
#endif
                /* file content request */
                req_size = data_to_uint64 (data);
                if (req_size >= filler->stbuf->ia_size) {

                        databuf = GF_CALLOC (1, filler->stbuf->ia_size,
                                             gf_metadata_mt_char);
                        if (!databuf) {
                                goto err;
                        }
                        ret = dict_set_bin (filler->xattr, key,
                                            databuf, filler->stbuf->ia_size);
                        if (ret < 0) {
                                gf_log (filler->this->name, GF_LOG_ERROR,
                                        "failed to set dict value. key: %s, path: %s",
                                        key, filler->loc->path);
                                goto err;
                        }
                        /* To avoid double free in cleanup below */
                        databuf = NULL;
                err:
                        GF_FREE (databuf);
                        databuf = NULL;
                }
			}else if (!strcmp (key, ZEFS_OPEN_FD_COUNT)) {
                loc = filler->loc;
                if (loc) {
                        ret = dict_set_uint32 (filler->xattr, key,
                                               loc->inode->fd_count);
                        if (ret < 0)
                                gf_log (filler->this->name, GF_LOG_WARNING,
                                        "Failed to set dictionary value for %s", key);
                }
        	}else {
				xattr   *xtr = NULL;
				xattr   *tmp_xtr = NULL;
				if (list_empty (&filler->fsnd->xattr_head))
	   				goto out;

				list_for_each_entry_safe(xtr, tmp_xtr, &filler->fsnd->xattr_head, attr_list){
					if(!strcmp(xtr->key, key)){
//gf_log (filler->this->name, GF_LOG_ERROR, "Test by hf@20150515 key=[%s], value=[%02x%02x]", key, xtr->value[2], xtr->value[3]);
						if(xtr && xtr->value){
							xattr_size = xtr->vallen;

   	                     	value = GF_CALLOC (1, xattr_size + 1,
                                           gf_metadata_mt_char);
                        	if (!value || xattr_size <= 0) {
                                gf_log (filler->this->name, GF_LOG_WARNING,
                                        "getxattr failed. path=%s, key=%s",
                                        filler->loc->path, key);
                                GF_FREE (value);
								value = NULL;
                                return -1;
                        	}

							memcpy(value, xtr->value, xattr_size);
                        	value[xattr_size] = '\0';

                        	ret = dict_set_bin (filler->xattr, key,
                                            value, xattr_size);
                        	if (ret < 0) {
                                gf_log (filler->this->name, GF_LOG_DEBUG,
                                        "dict set failed. path: %s, key: %s",
                                        loc->path, key);
                                GF_FREE (value);
							}
						}
						break;
					}
				}
		}
out:
        return 0; 
//gf_log("Testlog", GF_LOG_INFO, "-----xattr get key=[%s], values=[%s]", key, data->data);
}

dict_t *
metadata_lookup_xattr_get (xlator_t *this, loc_t *loc,
                         dict_t *xattr_req, struct iatt *buf, fsnode *fsnd)
{
        dict_t                      *xattr    = NULL;
        metadata_xattr_filler_t      filler   = {0, };

        xattr = get_new_dict();
        if (!xattr) {
                goto out;
        }

        filler.this      = this;
        filler.xattr     = xattr;
        filler.stbuf     = buf;
        filler.loc       = loc;
        filler.fsnd      = fsnd;

        dict_foreach (xattr_req, _metadata_xattr_get_set, &filler);
out:
        return xattr;
}

static int
_metadata_fd_ctx_get (fd_t *fd, xlator_t *this, struct mtdata_fd **pfd_p)
{
        uint64_t          tmp_pfd = 0;
        struct mtdata_fd  *pfd = NULL;
        int               ret = -1;

        ret = __fd_ctx_get (fd, this, &tmp_pfd);
        if (ret == 0) {
                pfd = (void *)(long) tmp_pfd;
                ret = 0;
                goto out;
        }

        if (!fd_is_anonymous(fd))
                /* anonymous fd */
                goto out;
        ret = 0;
//Lost fd&dir operation， 缺少fd和dir的操作，后续使用时在添加
out:
        if (pfd_p)
                *pfd_p = pfd;
        return ret;
}

int
metadata_fd_ctx_get (fd_t *fd, xlator_t *this, struct mtdata_fd **pfd)
{
        int   ret;

        LOCK (&fd->inode->lock);
        {
                ret = _metadata_fd_ctx_get (fd, this, pfd);
        }
        UNLOCK (&fd->inode->lock);

        return ret;
}


gf_boolean_t
metadata_special_xattr (char **pattern, char *key)
{
        int          i    = 0;
        gf_boolean_t flag = _gf_false;

        GF_VALIDATE_OR_GOTO ("posix", pattern, out);
        GF_VALIDATE_OR_GOTO ("posix", key, out);

        for (i = 0; pattern[i]; i++) {
                if (!fnmatch (pattern[i], key, 0)) {
                        flag = _gf_true;
                        break;
                }
        }
out:
        return flag;
}
int32_t
fsnode_xattr_from_key_get_value(fsnode *fsnd, const char *key, void *value, size_t size){
		int32_t            op_ret  = -1;
		xattr             *xtr     = NULL;
		xattr             *tmp_xtr = NULL;

		if (list_empty (&fsnd->xattr_head))
			goto out;

		list_for_each_entry_safe(xtr, tmp_xtr, &fsnd->xattr_head, attr_list){
			if(!strcmp(xtr->key, key)){
				if(xtr && xtr->value){
					memcpy((char*)value, xtr->value, size);
                	//(char*)value[size] = '\0';
				}
				op_ret = 0;
				goto out;
			}
		}

out:
		return op_ret;
}

int32_t
fsnode_list_all_xattr(xlator_t *this, fsnode *fsnd, dict_t *dict){
		int32_t            op_ret  = -1;
		int32_t            op_errno= ENOENT;
		xattr             *xtr     = NULL;
		xattr             *tmp_xtr = NULL;
		char              *value   = NULL;
		char               key[4096] = {0,};
		ssize_t            size      = 0;

		if (list_empty (&fsnd->xattr_head))
			goto out;

		list_for_each_entry_safe(xtr, tmp_xtr, &fsnd->xattr_head, attr_list){
			if(xtr && xtr->value){
				strcpy(key, xtr->key);
				size = xtr->vallen;
                value = GF_CALLOC (size + 1, sizeof(char),
                                   gf_metadata_mt_char);
                if (!value) {
                        op_ret = -1;
                        op_errno = errno;
                        goto out;
                }
				memcpy(value, xtr->value, size);

                value [size] = '\0';
                op_ret = dict_set_dynptr (dict, key, value, size);
                if (op_ret) {
                        gf_log (this->name, GF_LOG_ERROR, "dict set operation "
                                "failed on key %s", key);
                        GF_FREE (value);
                        goto out;
                }
			}

		}
		op_ret = size;
out:
	return op_ret;
}

int32_t
fsnode_xattr_get_value(xlator_t *this, dict_t *dict , 
				char *key, fsnode *fsnd)
{
		int32_t            op_ret  = -1;
		int32_t            size    = 0;
		xattr             *xtr     = NULL;
		xattr             *tmp_xtr = NULL;
		char *             value   = NULL;

		if (list_empty (&fsnd->xattr_head))
			goto out;

		list_for_each_entry_safe(xtr, tmp_xtr, &fsnd->xattr_head, attr_list){
		if(!strcmp(xtr->key, key)){
//gf_log (filler->this->name, GF_LOG_ERROR, "Test by hf@20150515 key=[%s], value=[%02x%02x]", key, xtr->value[2], xtr->value[3]);
			if(xtr && xtr->value){
				size = xtr->vallen;

   	           	value = GF_CALLOC (1, size + 1,
               					gf_metadata_mt_char);
				if (!value || size <= 0) {
                	gf_log (this->name, GF_LOG_WARNING,
                    	"getxattr failed. key=%s", key);
                         GF_FREE (value);
                         goto out;
                }

				memcpy(value, xtr->value, size);
                value[size] = '\0';

				op_ret = dict_set_dynptr (dict, key, value, size);
			     if (op_ret < 0) {
           	     		gf_log (this->name, GF_LOG_ERROR, "dict set operation "
                 				"on key %s failed", key);
 		         		GF_FREE (value);
				        goto out;
               	}
			}
			break;
		}
	}
	op_ret = size;
out:
	return op_ret;
}

// Add by hf@20150526 for fsedge hash used by BKDR Hash
unsigned int BKDRHash(char *str)
{
    unsigned int seed = 131;
    unsigned int hash = 0;

    while (*str)
    {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}

