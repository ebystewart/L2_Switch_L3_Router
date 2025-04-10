#include <stdio.h>
#include "graph.h"
#include "net.h"
#include "CommandParser/libcli.h"
#include "comm.h"

extern graph_t *build_first_topo(void);


graph_t *topo = NULL;

int main(int argc, char **argv)
{
    nw_init_cli();
    topo = build_first_topo();
    //dump_nw_graph(topo);
    sleep(2);
    node_t *snode = get_node_by_node_name(topo, "R0_re");
    printf("Node address: %x\n", snode);
    interface_t *oif = get_node_intf_by_name(snode, "eth0/0");
    printf("Interface address: %x\n", oif);
    char msg[] = "Hello! How are you?";
    send_pkt_out(msg, strlen(msg), oif);

    start_shell();
    return 0;
}