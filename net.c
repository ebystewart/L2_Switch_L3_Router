#include <stdio.h>
#include "net.h"
#include "graph.h"
#include "glueThread/glthread.h"

#if 0
static unsigned int hash_code(void *ptr, unsigned int size);

/*Just some Random number generator*/
static unsigned int hash_code(void *ptr, unsigned int size){
    unsigned int value=0, i =0;
    char *str = (char*)ptr;
    while(i < size)
    {
        value += *str;
        value*=97;
        str++;
        i++;
    }
    return value;
}
#endif    


/*Heuristics, Assign a unique mac address to interface*/
void interface_assign_mac_address(interface_t *interface, char *mac_addr){

    memset(IF_MAC(interface), 0, sizeof(IF_MAC(interface)));
    memcpy(IF_MAC(interface), mac_addr, sizeof(IF_MAC(interface)));
}

bool_t node_set_loopback_address(node_t *node, char *ip_addr)
{
    assert(ip_addr);
    node->node_nw_prop.is_lb_addr_config = TRUE;
    strcpy(NODE_LO_ADDRESS(node), ip_addr);//, 16);
    //NODE_LO_ADDRESS(node)[15] = '\0';
    return TRUE;
}

bool_t node_set_intf_ip_address(node_t *node, char *local_if, char *ip_addr, char mask)
{
    interface_t *interface = get_node_intf_by_name(node, local_if);
    strcpy(IF_IP(interface), ip_addr);//, 16);
    //IF_IP(interface)[15] = '\0';
    interface->intf_nw_prop.is_ipaddr_config = TRUE;
    interface->intf_nw_prop.mask = mask;
    return TRUE;
}

bool_t node_unset_intf_ip_address(node_t *node, char *local_if)
{
    return TRUE;
}

void dump_nw_graph(graph_t *graph)
{
    unsigned int i;
    node_t *node;
    glthread_t *curr;
    interface_t *interface;

    printf("Topology Name = %s\n", graph->topology_name);

    ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){
        node = graph_glue_to_node(curr);
        dump_node_nw_props(node);
        for(i = 0U; i < MAX_IF_PER_NODE; i++)
        {
            interface = node->intf[i];
            //printf("slot %u, interface pointer %x\n", i, interface);
            if(interface != NULL)
                dump_intf_props(interface);
        }
    }ITERATE_GLTHREAD_END(&graph->node_list, curr);
}

void dump_node_nw_props(node_t * node)
{
    printf("Node Name: %s\n", node->node_name);
    if(node->node_nw_prop.is_lb_addr_config){
        printf("\t Lo Address: %s/32\n", NODE_LO_ADDRESS(node));
    }
}

void dump_intf_props(interface_t *interface)
{
    dump_interface(interface);
    if(interface->intf_nw_prop.is_ipaddr_config){
        printf("\t IP Addr = %s/%u", IF_IP(interface), interface->intf_nw_prop.mask);
        printf("\t MAC = %u:%u:%u:%u:%u:%u\n", IF_MAC(interface)[0], IF_MAC(interface)[1], IF_MAC(interface)[2],
                                                IF_MAC(interface)[3], IF_MAC(interface)[4], IF_MAC(interface)[5]);
    }
    else{
        /* TBD */
    }

}