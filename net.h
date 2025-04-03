#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <memory.h>


#define TRUE  1U
#define FALSE 0U

typedef bool bool_t;
typedef struct graph_ graph_t;
typedef struct node_ node_t;
typedef struct interface_ interface_t;

typedef struct ip_add_{
    char ip_addr[16];
}ip_add_t;

typedef struct mac_add_{
    char mac_addr[6];
}mac_add_t;

typedef struct node_nw_prop_{
    /* L3 Properties*/
    bool_t is_lb_addr_config;
    ip_add_t lb_addr; /* Loopback address of the node */
}node_nw_prop_t;

typedef struct intf_nw_prop_{
    /* L2 Properties */
    mac_add_t mac_addr;

    /* L3 Properties */
    bool_t is_ipaddr_config;
    ip_add_t ip_addr;
    char mask;
}intf_nw_prop_t;

static inline void init_node_nw_prop(node_nw_prop_t *node_nw_prop);
static inline void init_intf_nw_prop(intf_nw_prop_t *intf_nw_prop);

static inline void init_node_nw_prop(node_nw_prop_t *node_nw_prop)
{
    node_nw_prop->is_lb_addr_config = FALSE;
    memset(&node_nw_prop->lb_addr, 0, 16);
}

static inline void init_intf_nw_prop(intf_nw_prop_t *intf_nw_prop)
{
    memset(&intf_nw_prop->mac_addr.mac_addr, 0, 6);
    intf_nw_prop->is_ipaddr_config = FALSE;
    memset(&intf_nw_prop->ip_addr.ip_addr, 0, 16);
    intf_nw_prop->mask = 0U;
}

#define IF_MAC(intf_ptr) ((intf_ptr)->intf_nw_prop.mac_addr.mac_addr)
#define IF_IP(intf_ptr)  ((intf_ptr)->intf_nw_prop.ip_addr.ip_addr)
#define NODE_LO_ADDRESS(node_ptr)  ((node_ptr)->node_nw_prop.lb_addr.ip_addr)

/* APIs to set network properties to nodes and interfaces */
void interface_assign_mac_address(interface_t *interface, char *mac_addr);
bool_t node_set_loopback_address(node_t *node, char *ip_addr);
bool_t node_set_intf_ip_address(node_t *node, char *local_if, char *ip_addr, char mask);
bool_t node_unset_intf_ip_address(node_t *node, char *local_if);

void dump_nw_graph(graph_t *graph);
void dump_node_nw_props(node_t * node);
void dump_intf_props(interface_t *interface);

#endif /* NET_H */