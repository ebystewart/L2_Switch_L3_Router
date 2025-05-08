#include "layer3.h"
#include <stdio.h>
#include <arpa/inet.h>
#include "ip.h"
#include "utils.h"
#include <string.h>

typedef bool bool_t;

/* Routing table APIs */

void init_rt_table(rt_table_t **rt_table){
    *rt_table = calloc(1, sizeof(rt_table_t));
    init_glthread(&((*rt_table)->route_list));
}

static bool_t rt_table_entry_add(rt_table_t *rt_table, l3_route_t *l3_route){
    l3_route_t *l3_route_old = rt_table_lookup(rt_table, l3_route->dest_ip, l3_route->mask_dest_ip);

    if(l3_route_old && IS_L3_ROUTES_EQUAL(l3_route_old, l3_route)){
        return FALSE;
    }
    if(l3_route_old){
        delete_rt_table_entry(rt_table, l3_route->dest_ip, l3_route->mask_dest_ip);
    }
    init_glthread(&l3_route->rt_glue);
    glthread_add_next(&rt_table->route_list, &l3_route->rt_glue);
    return TRUE;
}

static bool_t l3_is_direct_route(l3_route_t *l3_route)
{
    return l3_route->is_direct;
}

void rt_table_add_direct_route(rt_table_t *rt_table, char *dst_ip, char mask){
    rt_table_add_route(rt_table, dst_ip, mask, 0, 0);
}

void rt_table_add_route(rt_table_t *rt_table, char *dst_ip, char mask, char *gw_ip, char *oif){

    unsigned int dst_ip_int;
    char dst_str_with_mask[16];

    printf("Info: Destination Ip is %s\n", dst_ip);
    apply_mask(dst_ip, mask, dst_str_with_mask);
    printf("Info: Masked destination IP (subnet Id) is %s\n", dst_str_with_mask);
    inet_pton(AF_INET, dst_str_with_mask, &dst_ip_int);
    printf("Info: IP as integer is %d\n",dst_ip_int);
    l3_route_t *l3_route = l3rib_lookup_lpm(rt_table, dst_ip_int);
    /* Assert if route entry already exist */
    assert(!l3_route);

    l3_route = calloc(1, sizeof(l3_route_t));
    strncpy(l3_route->dest_ip, dst_str_with_mask, 16);
    l3_route->dest_ip[15] = '\0';
    l3_route->mask_dest_ip = mask;

    if(!gw_ip && !oif)
        l3_route->is_direct = TRUE;
    else
        l3_route->is_direct = FALSE;

    if(gw_ip && oif){
        strncpy(l3_route->gw_ip, gw_ip, 16);
        l3_route->dest_ip[15] = '\0';
        strncpy(l3_route->oif, oif, IF_NAME_SIZE);
        l3_route->oif[IF_NAME_SIZE - 1] = '\0';
    }

    if(rt_table_entry_add(rt_table, l3_route) == 0U){
        printf("Error: Route %s/%d installation failed \n", dst_str_with_mask, mask);
        free(l3_route);
    }
    //free(dst_str_with_mask);
}

l3_route_t *rt_table_lookup(rt_table_t *rt_table, char *ip_addr, char mask){

    l3_route_t *l3_route;
    glthread_t *curr;

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){
        l3_route = rt_glue_to_l3_route(curr);
        if((strncmp(l3_route->dest_ip, ip_addr, 16) == 0U) && (l3_route->mask_dest_ip == mask)){
            return l3_route;
        }
    }ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
}

/* Lookup routing table using longest prefix match */
l3_route_t *l3rib_lookup_lpm(rt_table_t *rt_table, uint32_t dst_ip){

    l3_route_t *l3_route = NULL;
    l3_route_t *lpm_l3_route = NULL;
    l3_route_t *default_l3_route = NULL;
    glthread_t *curr = NULL;

    char subnet[16];
    char dst_ip_str[16];
    char longest_mask = 0;

    dst_ip = htonl(dst_ip);
    inet_ntop(AF_INET, &dst_ip, dst_ip_str, 16);
    dst_ip_str[15] = '\0';

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        memset(subnet, 0, 16);
        apply_mask(dst_ip_str, l3_route->mask_dest_ip, subnet);
        printf("subnet id of %s with mask %d is %s\n", dst_ip_str, l3_route->mask_dest_ip, subnet);

        if((strncmp("0.0.0.0", l3_route->dest_ip, 16) == 0U) && (l3_route->mask_dest_ip == 0U)){
            default_l3_route = l3_route;
        }
        else if(strncmp(subnet, l3_route->dest_ip, strlen(subnet)) == 0U)
        { 
            printf("Comparing %s with %s\n",subnet, l3_route->dest_ip);
            if(l3_route->mask_dest_ip > longest_mask)
            {
                longest_mask = l3_route->mask_dest_ip;
                lpm_l3_route = l3_route;
            }
        }

    }ITERATE_GLTHREAD_END(&rt_table->route_list, curr);

    return (lpm_l3_route ? lpm_l3_route : default_l3_route);
}

void delete_rt_table_entry(rt_table_t *rt_table, char *ip_addr, char mask)
{
    char dst_ip_str_with_mask[16];
    apply_mask(ip_addr, mask, dst_ip_str_with_mask);

    l3_route_t *l3_route = rt_table_lookup(rt_table, dst_ip_str_with_mask, mask);
    if(!l3_route)
        return;
    remove_glthread(&l3_route->rt_glue);
    free(l3_route);
}

void clear_rt_table(rt_table_t *rt_table)
{
    l3_route_t *l3_route;
    glthread_t *curr;

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){
        l3_route = rt_glue_to_l3_route(curr);
        remove_glthread(&l3_route->rt_glue);
        free(l3_route);
    }ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
}

void dump_rt_table(rt_table_t *rt_table){
    l3_route_t *l3_route;
    glthread_t *curr;

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){
        l3_route = rt_glue_to_l3_route(curr);
        printf("\t%-18s %-4d %-18s %s\n",
                l3_route->dest_ip, l3_route->mask_dest_ip, 
                l3_route->is_direct ? "NA" : l3_route->gw_ip,
                l3_route->is_direct ? "NA" : l3_route->oif);
    }ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
}

/* Packet promotion APIs */
static void layer3_pkt_recv_from_top(node_t *node, char *pkt, unsigned int size, int protocol_number, unsigned int dest_ip_address)
{

}

/*An API to be used by L4 or L5 to push the pkt down the TCP/IP
 * stack to layer 3*/
void
demote_packet_to_layer3(node_t *node, 
                        char *pkt, unsigned int size,
                        int protocol_number, /*L4 or L5 protocol type*/
                        unsigned int dest_ip_address){

    layer3_pkt_recv_from_top(node, pkt, size, 
            protocol_number, dest_ip_address);
}

static void layer3_pkt_recv_from_bottom(node_t *node, interface_t *interface, char *pkt, unsigned int pkt_size, int L3_protocol_type)
{

}

/* A public API to be used by L2 or other lower Layers to promote
 * pkts to Layer 3 in TCP IP Stack*/
void promote_pkt_to_layer3(node_t *node,                /*Current node on which the pkt is received*/
                      interface_t *interface,           /*ingress interface*/
                      char *pkt, unsigned int pkt_size, /*L3 payload*/
                      int L3_protocol_number){          /*obtained from eth_hdr->type field*/

    layer3_pkt_recv_from_bottom(node, interface, pkt, pkt_size, L3_protocol_number);
}

/* Extern APIs which are to be defined in other layers*/
extern void
promote_pkt_to_layer4(node_t *node, interface_t *recv_intf, 
                      char *l4_hdr, unsigned int pkt_size,
                      int L4_protocol_number);

extern void
promote_pkt_to_layer5(node_t *node, interface_t *recv_intf, 
                      char *l5_hdr, unsigned int pkt_size,
                      int L5_protocol_number);


/* Packet Demotion APIs */
/*import function from layer 2*/
extern void
demote_pkt_to_layer2(node_t *node,
                     unsigned int next_hop_ip,
                     char *outgoing_intf, 
                     char *pkt, unsigned int pkt_size,
                     int protocol_number);