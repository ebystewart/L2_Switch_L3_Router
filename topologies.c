#include "graph.h"
#include "comm.h"


graph_t *build_first_topo(void)
{
/*

                      +----------+
                  0/4 |          |0/0
     +----------------+   R0_re  +---------------------------+
     |     40.1.1.1/24| 122.1.1.0|20.1.1.1/24                |
     |                +----------+                           |
     |                                                       |
     |                                                       |
     |                                                       |
     |40.1.1.2/24                                            |20.1.1.2/24
     |0/5                                                    |0/1
+----+----+                                              +----+-----+
|         |0/3                                        0/2|          |
|  R2_re  +----------------------------------------------+   R1_re  |
|         |30.1.1.2/24                        30.1.1.1/24|          |
+---------+                                              +----------+

*/

    graph_t *topo = create_new_graph("Hello World Generic Graph");
    node_t *R0_re = create_graph_node(topo, "R0_re");
    node_t *R1_re = create_graph_node(topo, "R1_re");
    node_t *R2_re = create_graph_node(topo, "R2_re");

    insert_link_between_two_nodes(R0_re, R1_re, "eth0/0", "eth0/1", 1);
    insert_link_between_two_nodes(R0_re, R2_re, "eth0/4", "eth0/5", 1);
    insert_link_between_two_nodes(R1_re, R2_re, "eth0/2", "eth0/3", 1);

    node_set_loopback_address(R0_re, "122.1.1.0");
    node_set_intf_ip_address(R0_re, "eth0/4", "40.1.1.1", 24);
    node_set_intf_ip_address(R0_re, "eth0/0", "20.1.1.1", 24);

    node_set_loopback_address(R1_re, "122.1.1.1");
    node_set_intf_ip_address(R1_re, "eth0/1", "20.1.1.2", 24);
    node_set_intf_ip_address(R1_re, "eth0/2", "30.1.1.1", 24);
    
    node_set_loopback_address(R2_re, "122.1.1.2");
    node_set_intf_ip_address(R2_re, "eth0/3", "30.1.1.2", 24);
    node_set_intf_ip_address(R2_re, "eth0/5", "40.1.1.2", 24); 
    
    network_start_pkt_receiver_thread(topo);

    return topo;
}