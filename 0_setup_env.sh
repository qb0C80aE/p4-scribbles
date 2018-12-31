#!/bin/bash
sudo ip link del v12
sudo ip link del v21
sudo ip link del v32
sudo ip link del v41
sudo ip netns del host1
sudo ip netns del host2
sudo ip netns del fw

sudo ip netns add host1
sudo ip netns add host2
sudo ip netns add fw

sudo ip netns exec fw iptables -A FORWARD -p tcp -j REJECT
sudo ip netns exec fw iptables -A FORWARD -p udp -j REJECT
sudo ip netns exec fw iptables -A FORWARD -p icmp -j ACCEPT
sudo ip netns exec fw iptables -A FORWARD -j REJECT

sudo ip link add v11 type veth peer name v12 # host1-term1
sudo ip link add v21 type veth peer name v22 # term1-fw
sudo ip link add v31 type veth peer name v32 # fw-term2
sudo ip link add v41 type veth peer name v42 # term2-host2

sudo ip link set dev v11 addr 10:54:ff:99:01:01
sudo ip link set dev v12 addr 10:54:ff:99:01:02
sudo ip link set dev v21 addr 10:54:ff:99:02:01
sudo ip link set dev v22 addr 10:54:ff:99:02:02
sudo ip link set dev v31 addr 10:54:ff:99:03:01
sudo ip link set dev v32 addr 10:54:ff:99:03:02
sudo ip link set dev v41 addr 10:54:ff:99:04:01
sudo ip link set dev v42 addr 10:54:ff:99:04:02

sudo ethtool --offload v11 rx off tx off
sudo ethtool --offload v12 rx off tx off
sudo ethtool --offload v21 rx off tx off
sudo ethtool --offload v22 rx off tx off
sudo ethtool --offload v31 rx off tx off
sudo ethtool --offload v32 rx off tx off
sudo ethtool --offload v41 rx off tx off
sudo ethtool --offload v42 rx off tx off

sudo ip link set v11 mtu 1480 # default - fake icmp(20)
sudo ip link set v42 mtu 1480 # default - fake icmp(20)

sudo ip link set v11 netns host1
sudo ip link set v22 netns fw
sudo ip link set v31 netns fw
sudo ip link set v42 netns host2
sudo ip netns exec host1 ip link set v11 up
sudo ip link set v12 up
sudo ip link set v21 up
sudo ip netns exec fw ip link set v22 up
sudo ip netns exec fw ip link set v31 up
sudo ip link set v32 up
sudo ip link set v41 up
sudo ip netns exec host2 ip link set v42 up

sudo ip netns exec host1 ip link set lo up
sudo ip netns exec host2 ip link set lo up
sudo ip netns exec fw ip link set lo up

sudo ip netns exec host1 ip addr add 10.0.0.1/24 dev v11
sudo ip netns exec fw ip addr add 10.0.0.254/24 dev v22
sudo ip netns exec fw ip addr add 10.0.1.254/24 dev v31
sudo ip netns exec host2 ip addr add 10.0.1.1/24 dev v42

sudo ip netns exec host1 ip route add 10.0.1.0/24 via 10.0.0.254                         
sudo ip netns exec host2 ip route add 10.0.0.0/24 via 10.0.1.254
sudo ip netns exec fw bash -c "echo 1 | tee /proc/sys/net/ipv4/ip_forward"

