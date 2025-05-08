#include "layer2.h"
#include "l2switch.h"
#include "comm.h"
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "tcpconst.h"


void node_set_intf_l2_mode(node_t *node, char *intf_name, intf_l2_mode_t intf_l2_mode)
{
    interface_t *intf = get_node_intf_by_name(node, intf_name);
    assert(intf);
    //intf->intf_nw_prop.intf_l2_mode = intf_l2_mode;
    interface_set_l2_mode(node, intf, intf_l2_mode_str(intf_l2_mode));
}

void interface_set_l2_mode(node_t *node, interface_t *interface, char *l2_mode_option)
{
    /* choose the L2 mode based on input parameter */
    intf_l2_mode_t intf_l2_mode;
    if(strncmp(l2_mode_option, "access", strlen("access")) == 0U){
        intf_l2_mode = ACCESS;
    }
    else if(strncmp(l2_mode_option, "trunk", strlen("trunk")) == 0U){
        intf_l2_mode = TRUNK;
    }
    else{
        intf_l2_mode = L2_MODE_UNKNOWN;
        assert(0);
    }

    /* Case 1: If interface was working in L3 mode (i.e an IP address is configured),
    disable the IP address and configured interface to L2 mode */
    if(IS_INTF_L3_MODE(interface)){
        interface->intf_nw_prop.is_ipaddr_config = FALSE;
        interface->intf_nw_prop.is_apaddr_config_prev = TRUE;
        IF_L2_MODE(interface) = intf_l2_mode;
        return;
    }

    /* Case 2: If interface is so for neither in L2 mode nor L3 mode, then, set l2 mode now */
    if(IF_L2_MODE(interface) == L2_MODE_UNKNOWN){
        IF_L2_MODE(interface) = intf_l2_mode;
        return;
    }

    /* case 3: If interface is already configured as L2 mode, and user requests for the same again, ignore and return */
    if(IF_L2_MODE(interface) == intf_l2_mode){
        return;
    }

    /* case 4: If interface is configured in ACCESS mode, and TRUNK mode is requested, overwrite */
    if(IF_L2_MODE(interface) == ACCESS && intf_l2_mode == TRUNK){
        IF_L2_MODE(interface) = intf_l2_mode;
        /* will have to add necssary vlan ids for trunk mode configuration to complete */
        return;
    }

    /* Case 5: If interface is configured in TRUNK mode, and ACCESS mode is requested, 
       change L2 mode and clean all vlan Ids tagged */
       if(IF_L2_MODE(interface) == TRUNK && intf_l2_mode == ACCESS){
        unsigned int i = 0U;
        for(; i < MAX_VLAN_MEMBERSHIP; i++){
            interface->intf_nw_prop.vlans[i] = 0U;
        }
        IF_L2_MODE(interface) = intf_l2_mode;
        //return;
       }
}

void node_set_intf_vlan_membership(node_t *node, char *intf_name, unsigned int vlan_id)
{
    interface_t *intf = get_node_intf_by_name(node, intf_name);
    assert(intf);
    interface_set_vlan(node, intf, vlan_id);
}

void interface_set_vlan(node_t *node, interface_t *intf, unsigned int vlan_id)
{
    /* Case 1 : Can't tag vlan id for an interface configured with IP address */
    if(IS_INTF_L3_MODE(intf)){
        printf("Error: L3 Mode enabled in interface %s\n", intf->if_name);
        return;
    }

    /* Case 2: Can't set vlan on interface not configured in L2 mode */
    if((IF_L2_MODE(intf) != ACCESS) && (IF_L2_MODE(intf) != TRUNK)){
        printf("Error: L2 mode not enabled in interface %s\n", intf->if_name);
        return;
    }

    /* Case 3: Can set only one vlan on interface operating in ACCESS mode*/
    if(intf->intf_nw_prop.intf_l2_mode == ACCESS){
        unsigned int i = 1U;
        unsigned int count = 0U;
        unsigned int *vlan = NULL;

        for (; i < MAX_VLAN_MEMBERSHIP; i++)
        {
            if (intf->intf_nw_prop.vlans[i])
            {
                intf->intf_nw_prop.vlans[i] = 0U;
                count++;
            }
        }
        if(count)
            printf("Interface %s in access mode configured with more than one vlan Id\n", intf->if_name);
        intf->intf_nw_prop.vlans[i] = vlan_id;
    }

    /* Case 4 : Add vlan membership for interface operating in TRUNK mode */
    if(intf->intf_nw_prop.intf_l2_mode == TRUNK)
    {
        unsigned int i = 0U;
        /* Search for duplicated entries */
        for(; i < MAX_VLAN_MEMBERSHIP; i++)
        {
            if(intf->intf_nw_prop.vlans[i] == vlan_id)
            {
                return;
            }
            else if(intf->intf_nw_prop.vlans[i] == 0U)
            {
                intf->intf_nw_prop.vlans[i] = vlan_id;
                return;
            }
        }
        printf("Error: Max vlan slot per interface of %s exceeded, increase the vlan slot size\n", intf->if_name);
    }
}

// caller needs to free calloc-ed memory after copying to actual buffer */
ethernet_frame_t *tag_pkt_with_vlan_id(ethernet_frame_t *eth_pkt, unsigned int total_pkt_size, \
    int vlan_id, unsigned int *new_pkt_size)
{
    vlan_8021q_hdr_t *vlan_hdr;
    vlan_hdr = is_pkt_vlan_tagged(eth_pkt);
    if(!vlan_hdr){
        vlan_ethernet_frame_t *vlan_eth_pkt = calloc(1, sizeof(vlan_ethernet_frame_t));
        memset(vlan_eth_pkt, 0, sizeof(vlan_ethernet_frame_t));

        /*set up vlan header first */
        vlan_eth_pkt->vlan_8021q_hdr.tpid = 0x8100U;
        vlan_eth_pkt->vlan_8021q_hdr.tci_vid = vlan_id;
        vlan_eth_pkt->vlan_8021q_hdr.tci_dei = 0U;
        vlan_eth_pkt->vlan_8021q_hdr.tci_pcp = 0U;

        /* set up ethernet header */
        memcpy(&vlan_eth_pkt->dst_mac, &eth_pkt->dst_mac, sizeof(mac_add_t));
        memcpy(&vlan_eth_pkt->src_mac, &eth_pkt->src_mac, sizeof(mac_add_t));
        vlan_eth_pkt->type = eth_pkt->type;
        memcpy(&vlan_eth_pkt->payload, eth_pkt->payload, (total_pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD));
        /* Actually FCS should be re-calculated - we ignore it for now */
        *new_pkt_size = total_pkt_size + sizeof(vlan_8021q_hdr_t);
        return (ethernet_frame_t *)&vlan_eth_pkt;
    }
    else{
        vlan_hdr->tci_vid = vlan_id;
        *new_pkt_size = total_pkt_size;
        return eth_pkt;
    }
    return NULL;
}

ethernet_frame_t *untag_pkt_with_vlan_id(ethernet_frame_t *eth_pkt, unsigned int total_pkt_size, unsigned int *new_pkt_size)
{
    vlan_8021q_hdr_t *vlan_hdr;
    vlan_hdr = is_pkt_vlan_tagged(eth_pkt);
    if(!vlan_hdr){
        return eth_pkt;
    }
    else{
        *new_pkt_size = total_pkt_size - sizeof(vlan_8021q_hdr_t);
        ethernet_frame_t *ethernet_pkt = calloc(1, *new_pkt_size );
        memset(ethernet_pkt, 0, *new_pkt_size);
        memcpy(&ethernet_pkt->dst_mac, &eth_pkt->dst_mac, sizeof(mac_add_t));
        memcpy(&ethernet_pkt->src_mac, &eth_pkt->src_mac, sizeof(mac_add_t));
        memcpy(&ethernet_pkt->payload, &eth_pkt->payload, (*new_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD));
        ethernet_pkt->type = eth_pkt->type;
        /* FCS should be calculated a-fresh */
        return ethernet_pkt;
    }
    return NULL;
}

void layer2_frame_recv(node_t *node, interface_t *interface, char *pkt, unsigned int pkt_size)
{
    unsigned int vlan_id_to_tag = 0U;
    /* Entry in to TCP IP stack from MAC Layer */
    if(l2_frame_recv_qualify_on_interface(interface, (ethernet_frame_t *)pkt, &vlan_id_to_tag) == FALSE){
        printf("L2 frame rejected on node %s\n", node->node_name);
        return;
    }
    printf("L2 frame accepted on node %s\n", node->node_name);

    /* handle reception of a L2 frame on an L3 interface */
    if(IS_INTF_L3_MODE(interface)){
        promote_pkt_to_layer2(node, interface, (ethernet_frame_t *)pkt, pkt_size);
    }
    else if(IF_L2_MODE(interface) == TRUNK || IF_L2_MODE(interface) == ACCESS){
        unsigned int new_pkt_size = 0U;

        if(vlan_id_to_tag){
            pkt = (char *)tag_pkt_with_vlan_id((ethernet_frame_t *)pkt, pkt_size, vlan_id_to_tag, &new_pkt_size);
            assert(new_pkt_size != pkt_size);
        }
        l2_switch_recv_frame(interface, pkt, vlan_id_to_tag? new_pkt_size : pkt_size);
    }
    else    
        return; /* Do nothing; drop the pkt */
}

static void promote_pkt_to_layer2(node_t *node, interface_t *interface, ethernet_frame_t *eth_frame, unsigned int pkt_size)
{
    switch(eth_frame->type)
    {
        case ARP_MSG:
        {
            arp_packet_t * arp_pkt = (arp_packet_t *)&eth_frame->payload;
            switch(arp_pkt->op_code)
            {
                case ARP_BROAD_REQ:
                {
                    process_arp_broadcast_request(node, interface, eth_frame);
                    break;
                }
                case ARP_REPLY:
                {
                    process_arp_reply_msg(node, interface, eth_frame);
                    break;
                }
                default:
                    break;
            }
        }
        case ETH_IP:
        {
            //promote_pkt_to_layer3()
            break;
        }
        default:
        ;
    }
}

void init_arp_table(arp_table_t **arp_table)
{
    *arp_table = calloc(0, sizeof(arp_table_t));
    init_glthread(&((*arp_table)->arp_entries));
}
/* CRUD ops for ARP table */
bool_t arp_table_entry_add(arp_table_t *arp_table, arp_entry_t *arp_entry)
{
    arp_entry_t *arp_entry_old = arp_table_lookup(arp_table, arp_entry->ip_addr.ip_addr);
    //if(strncmp(arp_entry_old->ip_addr.ip_addr, arp_entry->ip_addr.ip_addr, sizeof(ip_add_t))){}
    if(arp_entry_old && memcmp(arp_entry_old, arp_entry, sizeof(arp_entry_t)) == 0U){
        return FALSE;
    }
    /* if above condition didn't return */
    if(arp_entry_old)
    {
        delete_arp_table_entry(arp_table, arp_entry_old->ip_addr.ip_addr);
    }

    init_glthread(&arp_entry->arp_glue);
    glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
    return TRUE;
}

arp_entry_t *arp_table_lookup(arp_table_t *arp_table, char *ip_addr)
{
    glthread_t *curr;
    arp_entry_t *arp_entry;

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        arp_entry = arp_glue_to_arp_entry(curr);
        if(strncmp(arp_entry->ip_addr.ip_addr, ip_addr, 16) == 0U)
            return arp_entry;
    }ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
    return NULL;
}

void arp_table_update_from_arp_reply(arp_table_t *arp_table, arp_packet_t *arp_pkt, interface_t *iif)
{
    unsigned int src_ip;
    assert(arp_pkt->op_code == ARP_REPLY);
    arp_entry_t *arp_entry = calloc(1, sizeof(arp_entry_t));
    src_ip = htonl(arp_pkt->src_ip);
    inet_ntop(AF_INET, &src_ip, &arp_entry->ip_addr.ip_addr, 16);
    /* To be on safer side */
    arp_entry->ip_addr.ip_addr[15] = '\0';
    memcpy(arp_entry->mac_addr.mac_addr, arp_pkt->src_mac.mac_addr, sizeof(mac_add_t));
    strncpy(arp_entry->oif_name, iif->if_name, IF_NAME_SIZE);

    bool_t rc = arp_table_entry_add(arp_table, arp_entry);
    if(!rc){
        free(arp_entry);
    }
}

void delete_arp_table_entry(arp_table_t *arp_table, char *ip_addr)
{
    glthread_t *curr;
    arp_entry_t *arp_entry;

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        arp_entry = arp_glue_to_arp_entry(curr);
        if(strncmp(arp_entry->ip_addr.ip_addr, ip_addr, 16) == 0U){
            remove_glthread(&arp_entry->arp_glue);
            free(arp_entry);
        }
    }ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
}

void dump_arp_table(arp_table_t *arp_table)
{
    glthread_t *curr;
    arp_entry_t *arp_entry;
    printf("*********ARP TABLE**********\n");
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        arp_entry = arp_glue_to_arp_entry(curr);
        printf("IP: %s, MAC: %u:%u:%u:%u:%u:%u, OIF: %s\n",
            arp_entry->ip_addr.ip_addr,
            arp_entry->mac_addr.mac_addr[0],
            arp_entry->mac_addr.mac_addr[1],
            arp_entry->mac_addr.mac_addr[2],
            arp_entry->mac_addr.mac_addr[3],
            arp_entry->mac_addr.mac_addr[4],
            arp_entry->mac_addr.mac_addr[5],
            arp_entry->oif_name);
    }ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
}

void send_arp_broadcast_request(node_t *node, interface_t *oif, char * ip_addr)
{
    //arp_packet_t *arp_pkt;
    unsigned int payload_size = sizeof(arp_packet_t);
    ethernet_frame_t *eth_frame = calloc(1, ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size);

    /* ARP resolution is meant to be with another subnet. 
       Find the matching interface for the dst IP address, if oif is not specified */
    if(!oif){
        oif = node_get_matching_subnet_interface(node, ip_addr);
        if(!oif){
            printf("Error: No matching interface for IP address %s found in node %s\n", ip_addr, node->node_name);
            return;
        }
        if(strncmp(IF_IP(oif), ip_addr, 16) == 0U){
            printf("Error: IP address %s is local within the same subnet\n", ip_addr);
            return;
        }
    }
    /* #1 Prepare ethernet header */
    layer2_fill_with_broadcast_mac(eth_frame->dst_mac.mac_addr);
    memcpy(eth_frame->src_mac.mac_addr, IF_MAC(oif), sizeof(mac_add_t));
    eth_frame->type = ARP_MSG;

    /* #2 Prepare ARP packet */
    /* Add ARP packet as payload to ethernet frame */
    arp_packet_t *arp_pkt = (arp_packet_t *)&eth_frame->payload;
    //arp_packet_t *arp_pkt = (arp_packet_t *)GET_ETHERNET_HDR_PAYLOAD(eth_pkt);
    memcpy(arp_pkt->src_mac.mac_addr, IF_MAC(oif), sizeof(mac_add_t));
    memset(arp_pkt->dst_mac.mac_addr, 0, sizeof(mac_add_t));
    arp_pkt->hw_addr_len = sizeof(mac_add_t);
    arp_pkt->proto_addr_len = 4U;
    arp_pkt->hw_type = 1U;
    arp_pkt->proto_type = 0x0800U;
    arp_pkt->op_code = ARP_BROAD_REQ;

    inet_pton(AF_INET, IF_IP(oif), &arp_pkt->src_ip);
    arp_pkt->src_ip = htonl(arp_pkt->src_ip);
    inet_pton(AF_INET, ip_addr, &arp_pkt->dst_ip);
    arp_pkt->dst_ip = htonl(arp_pkt->dst_ip);

    /* #3 append the ethernet footer */
    SET_COMMON_ETH_FCS(eth_frame, sizeof(arp_packet_t), 0U); /* 0 because, it is NOT used for now */

    /* #4  send  out the ethernet frame */
    send_pkt_out(eth_frame, (ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size), oif);
    free(eth_frame);
}

static void send_arp_reply_msg(ethernet_frame_t *eth_frame_in, interface_t *oif)
{
    arp_packet_t *arp_pkt_in = (arp_packet_t *)&eth_frame_in->payload;

    ethernet_frame_t *eth_frame_reply = calloc(1, MAX_SEND_BUFFER_SIZE);
    memcpy(eth_frame_reply->src_mac.mac_addr, IF_MAC(oif), sizeof(mac_add_t));
    memcpy(eth_frame_reply->dst_mac.mac_addr, arp_pkt_in->src_mac.mac_addr, sizeof(mac_add_t));
    eth_frame_reply->type = ARP_MSG;

    arp_packet_t *arp_pkt_reply = (arp_packet_t *)&eth_frame_reply->payload;
    arp_pkt_reply->hw_type = 1U;
    arp_pkt_reply->hw_addr_len = sizeof(mac_add_t);
    arp_pkt_reply->proto_type = 0x0800;
    arp_pkt_reply->proto_addr_len = 4U;
    arp_pkt_reply->op_code = ARP_REPLY;
    memcpy(arp_pkt_reply->src_mac.mac_addr, IF_MAC(oif), sizeof(mac_add_t));
    memcpy(arp_pkt_reply->dst_mac.mac_addr, arp_pkt_in->src_mac.mac_addr, sizeof(mac_add_t));

    inet_pton(AF_INET, IF_IP(oif), &arp_pkt_reply->src_ip);
    arp_pkt_reply->src_ip = htonl(arp_pkt_reply->src_ip);

    memcpy(arp_pkt_reply->dst_ip, arp_pkt_in->dst_ip, 16U);

    SET_COMMON_ETH_FCS(eth_frame_reply, (ETH_HDR_SIZE_EXCL_PAYLOAD_FCS + sizeof(arp_packet_t)), 0);

    unsigned int total_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_packet_t);
    char * shifted_pkt_buffer = pkt_buffer_shift_right((char *)eth_frame_reply, total_pkt_size, MAX_SEND_BUFFER_SIZE);
    send_pkt_out(shifted_pkt_buffer, total_pkt_size, oif);
    free(eth_frame_reply);
} 

static void process_arp_reply_msg(node_t *node, interface_t *iif, ethernet_frame_t *eth_frame)
{
    printf("ARP reply message received on interface %s of node %s\n", iif->if_name, node->node_name);
    arp_table_update_from_arp_reply(NODE_ARP_TABLE(node), (arp_packet_t *)GET_ETHERNET_HDR_PAYLOAD(eth_frame), iif);
}

static void process_arp_broadcast_request(node_t *node, interface_t *iif, ethernet_frame_t *eth_frame)
{
    printf("ARP broadcast msg received on interface %s of node %s\n", iif->if_name, node->node_name);

    char ip_addr[16];
    arp_packet_t *arp_pkt = (arp_packet_t *)&eth_frame->payload;
    unsigned int arp_dst_ip = htonl(arp_pkt->dst_ip);
    inet_ntop(AF_INET, &arp_dst_ip, ip_addr, 16U);//??
    if(strncmp(IF_IP(iif), ip_addr, 16))
    {
        printf("ARP request msg dropped as the interface Ip doesn't match with the ARP requested IP\n");
        return;
    }
    send_arp_reply_msg(eth_frame, iif);
}


