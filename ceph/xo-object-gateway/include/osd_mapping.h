#ifndef __OSD_MAPPING_H__
#define __OSD_MAPPING_H__

#define MAX_OSDS 64

extern char *osd_addr_strs[MAX_OSDS];
extern struct sockaddr_in osd_addrs[MAX_OSDS];
extern int osd_ids[MAX_OSDS];
extern int num_osds;
extern int num_peers;

extern uint8_t my_mac[6];

// FUTURE TODO: add a data structure to optimize this linear search?
static inline int get_arr_index_from_osd_id(int osd_id)
{
    for (int i = 0; i < num_osds; i++)
    {
        if (osd_ids[i] == osd_id)
            return i;
    }
    fprintf(stderr, "%s: cant find osd_id %d in array\n",
        __func__, osd_id);
    return -1;
}

static inline struct sockaddr_in get_my_osd_addr()
{
    return osd_addrs[num_osds - 1];
}

static inline char *get_my_osd_addr_str()
{
    return osd_addr_strs[num_osds - 1];
}

static inline int get_my_osd_id()
{
    return osd_ids[num_osds - 1];
}

#endif
