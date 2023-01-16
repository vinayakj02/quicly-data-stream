from nest.topology import Node 
from nest import config
from nest.topology import connect

config.set_value("assign_random_names", False)
config.set_value("delete_namespaces_on_termination", False)

client = Node('h1')
server = Node('h2')

h1_h2 , h2_h1 = connect(client, server, 'h1_h2', 'h2_h1')
h1_h2.set_address('10.0.0.1/24')
h2_h1.set_address('10.0.0.2/24')
