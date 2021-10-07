import json, copy

class TopologyDB:
    """
    Topology API to load the topology and get some useful information
    about the network

    Attributes:
        topo_file  : string  //path to the json file that describes the network
        file  : string  //name of the file where the script is calling from

    """

    def __init__(self, topo_file, file):

        topo_file = "../../exercises/" + file + "/" + topo_file
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        #print "{}".format(topo['hosts'])
        #print "\n"
        self.switches = topo['switches']
        #print "{}".format(topo['switches'])
        #print "\n"
        self.links = self.parse_links(topo['links'])
        #for link in self.links:
        #    print "links: NODE2: {} \n ".format(link['node2'].rsplit('-')[0])


    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s,t = t,s

            link_dict = {'node1':s,
                        'node2':t,
                        'latency':'0ms',
                        'bandwidth':None
                        }
            if len(link) > 2:
                link_dict['latency'] = self.format_latency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(link_dict['node2'])
            links.append(link_dict)
        return links

    def get_node_neighbors(self, node):
        if not (node in self.hosts or node in self.switches):
            raise AssertionError('There is no node named {} in this topology.'.format(node))

        neighbors = []
        for link in self.links:
            if node == link['node1'].rsplit('-')[0] or node == link['node2'].rsplit('-')[0]:
                if node in link['node1']:
                    neighbors.append(link['node2'].rsplit('-')[0])
                else:
                    neighbors.append(link['node1'].rsplit('-')[0])

        return neighbors

#get all nodes's neighbors that are hosts
    def get_hosts_neighbors(self, node):
        if not (node in self.hosts or node in self.switches):
            raise AssertionError('There is no node named {} in this topology.'.format(node))

        neighbors = []
        for link in self.links:
            if node == link['node1'].rsplit('-')[0] or node == link['node2'].rsplit('-')[0]:
                if 'h' == link['node1'][0]:
                    if node in link['node1']:
                        neighbors.append(link['node2'].rsplit('-')[0])
                    else:
                        neighbors.append(link['node1'].rsplit('-')[0])
        return neighbors

# Get the neighbor that is connected to the given port
    def get_neighbor_by_port(self, node, port):
        if not (node in self.hosts or node in self.switches):
            raise AssertionError('There is no node named {} in this topology.'.format(node))

        port = str(port)
        for link in self.links:
            if node == link['node1'].rsplit('-')[0] and port == link['node1'].rsplit('p')[1]:
                return link['node2'].rsplit('-')[0]
            elif node == link['node2'].rsplit('-')[0] and port == link['node2'].rsplit('p')[1]:
                return link['node1'].rsplit('-')[0]

        raise AssertionError('There is no node {} with port {} in this topology'.format(node, port))

    def get_host_ip(self, host):
        if not host in self.hosts:
            raise AssertionError('There is no host named {} in this topology.'.format(host))

        return self.hosts[host]['ip']

    def get_host_mac(self, host):
        if not host in self.hosts:
            raise AssertionError('There is no host named {} in this topology.'.format(host))

        return self.hosts[host]['mac']

    def get_switch_mac(self, switch):
        if not switch in self.switches:
            raise AssertionError('There is no switch named {} in this topology.'.format(switch))

        neighbors = self.get_hosts_neighbors(switch)
        return self.hosts[neighbors[0]]['commands'][1][-17:]

    def get_switch_cpu_port(self, switch):
        if not switch in self.switches:
            raise AssertionError('There is no switch named {} in this topology.'.format(switch))

        print(self.switches[switch]['cpu_port'])
        return(self.switches[switch]['cpu_port'])

    def get_all_node_interfaces(self, node):
        if not node in self.switches:
            raise AssertionError('There is no switch named {} in this topology.'.format(node))

        link_list = []

        for link in self.links:
            if link['node1'].rsplit('-')[0] == node and link['node1'].rsplit('p')[1] not in link_list:
                link_list.append(link['node1'].rsplit('p')[1])
            elif link['node2'].rsplit('-')[0] == node and link['node2'].rsplit('p')[1] not in link_list:
                link_list.append(link['node2'].rsplit('p')[1])
        return link_list

#This funtion will get the node's interface that connect to the given neighbor
    def get_node_interface(self, node, neighbor):
        if not node in self.switches:
            raise AssertionError('There is no switch named {} in this topology.'.format(node))
        if not(neighbor in self.switches or neighbor in self.hosts):
            raise AssertionError('There is no switch or host named {} in this topology'.format(neighbor))
        devices = self.get_node_neighbors(node)
        if not neighbor in devices:
            raise AssertionError('The two given devices are not connected to each other')

        for link in self.links:
            if node == link['node1'].rsplit('-')[0] and neighbor == link['node2'].rsplit('-')[0]:
                return link['node1'].rsplit('-')[1].rsplit('p')[1]
            elif neighbor == link['node1'].rsplit('-')[0] and node == link['node2'].rsplit('-')[0]:
                return link['node2'].rsplit('-')[1].rsplit('p')[1]


if __name__ == '__main__':
    #testing
    topo = "topology.json"
    file = "Scappy_test_v2"
    topo = TopologyDB(topo, file)
    print (topo.get_neighbor_by_port('s3', 2))
    print (topo.get_neighbor_by_port('s3', 4))
