/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.zecloud.cn>
   This file is part of ZeFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef __METADATA__MEM_TYPES_H__
#define __METADATA__MEM_TYPES_H__

#include "mem-types.h"

enum gf_metadata_mem_types_ {
        gf_metadata_int32_t = gf_common_mt_end + 1,
        gf_metadata_mt_private_t,
        gf_metadata_mt_table_t,
        gf_metadata_mt_xlator_t,
        gf_metadata_mt_fsnode_t,
        gf_metadata_mt_fsedge_t,
		gf_metadata_mt_char,          // Add by hf@20150409  
		gf_metadata_mt_fsnode_fd,          // Add by hf@20150530
		gf_defrag_mt_info_t,          /* add by hf */
        gf_metadata_mt_end
};
#endif
