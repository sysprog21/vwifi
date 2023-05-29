# vwifi: A Simple Virtual Wireless Driver for Linux

`vwifi` implements a minimal interface to achieve basic functionalities,
such as scanning dummy Wi-Fi networks, connecting, and disconnecting from them.
It is based on the [cfg80211 subsystem](https://www.kernel.org/doc/html/latest/driver-api/80211/cfg80211.html),
which works together with FullMAC drivers.
Currently, it supports station mode and Host AP mode.

## Prerequisite

The following packages must be installed before building `vwifi`.

To compile the kernel driver successfully, the package versions of the currently used kernel,
kernel-devel, and kernel-headers need to be matched. Run the following command to install the required kernel headers:
```shell
$ sudo apt install linux-headers-$(uname -r)
```

Since `vwifi` relies on the Linux wireless (IEEE-802.11) subsystem, [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw) is necessary for retrieving more information and configuring.
Install it using the following command:
```shell
$ sudo apt install iw
```

If running the test script (scripts/verify.sh), Python 3, hostapd, and some additional packages are necessary.
```shell
$ sudo apt install python3 python3-pip hostapd
$ pip3 install numpy matplotlib
```

## Testing environment

<p align="center"><img src="assets/vwifi.png" alt="logo image" width=60%></p>

The testing environment consists of **one AP and two STAs**.

The testing environment operates in IEEE 802.11 infrastructure BSS, which imposes a constraint: **STAs cannot directly communicate with each other**.
When an STA wants to communicate with other devices, it must send packets to the AP.
The AP then performs the following actions based on the packet type:
1. Unicast: If the packet is intended for another STA, the AP forwards it directly to the destination STA without passing it to the protocol stack.
   If the packet is intended for the AP itself, it is passed to the protocol stack.
2. Broadcast: The AP forwards the packet to all other STAs in the network, except for the source STA, and then passes it to the protocol stack.
3. Multicast: The AP treats multicast packets the same way as broadcast packets.

To test the network environment, we can utilize the **Linux network namespace**.
Linux network namespace allows us to isolate a network environment from the host system, providing its own routes, firewall rules, and network devices.
Essentially, it creates a separate instance of the network stack.

Without network namespace, when virtual interfaces are created that share the same network namespace and start transmitting/receiving packets between them,
the kernel will use the loopback device for packet transmission/reception. This behavior occurs because the kernel identifies that the sender and receiver are on the same host.

In conclusion, all the interfaces created by `vwifi` in the testing environment will be added to an isolated network namespace.

## Build and Run

To build the kernel module, execute the following command:
```shell
$ make
```

Load the cfg80211 kernel module by running the following command:
```shell
$ sudo modprobe cfg80211
```

Insert the `vwifi` driver.
This will create three interfaces (the "station" parameter can be modified according to preference):
```shell
$ sudo insmod vwifi.ko station=3
```

Please note that interfaces can only be created in station mode during the initialization phase.
However, they can be switched to Host AP mode later using hostapd.

### Checking Network Interfaces

To check the network interfaces, run the following command:
```shell
$ ip link
```

There should be entries starting with `owl0`, `owl1`, and `owl2`, which correspond to the interfaces created by `vwifi`.

To view the available wireless interfaces, execute the following command:
```shell
$ sudo iw dev
```

You should see something similar to the following output:
```
phy#13
	Interface owl2
		ifindex 16
		wdev 0xd00000001
		addr 00:6f:77:6c:32:00
		type managed
phy#12
	Interface owl1
		ifindex 15
		wdev 0xc00000001
		addr 00:6f:77:6c:31:00
		type managed
phy#11
	Interface owl0
		ifindex 14
		wdev 0xb00000001
		addr 00:6f:77:6c:30:00
		type managed
```

As observed, each interface has its own phy (`struct wiphy`), allowing them to be placed into separate network namespaces.

### Dumping Wireless Information

To obtain wireless information, execute the following command:
```shell
$ sudo iw list
```

Reference output:
```
Wiphy phy13
	max # scan SSIDs: 69
	max scan IEs length: 0 bytes
	max # sched scan SSIDs: 0
	max # match sets: 0
	Retry short limit: 7
	Retry long limit: 4
	Coverage class: 0 (up to 0m)
	Available Antennas: TX 0 RX 0
	Supported interface modes:
		 * managed
		 * AP
	Band 1:
		Bitrates (non-HT):
			* 1.0 Mbps
			* 2.0 Mbps
			* 5.5 Mbps
			* 11.0 Mbps
		Frequencies:
			* 2437 MHz [6] (20.0 dBm)
	Supported commands:
		 * set_interface
		 * start_ap
		 * set_wiphy_netns
		 * set_channel
		 * connect
		 * disconnect
	software interface modes (can always be added):
	interface combinations are not supported
	Device supports scan flush.
	max # scan plans: 1
	max scan plan interval: -1
	max scan plan iterations: 0
	Supported extended features:
Wiphy phy14
	... (omit)
Wiphy phy15
	... (omit)
```

The "managed mode" in the Supported interface modes is identical to station mode.

### Getting Station Information

To retrieve station information for `owl0`, execute the following command:
```shell
$ sudo iw dev owl0 station get 00:6f:77:6c:30:00
```

You should see output similar to the following:
```
Station 00:6f:77:6c:30:00 (on owl0)
	inactive time:	600260 ms
	rx bytes:	0
	rx packets:	0
	tx bytes:	0
	tx packets:	0
	tx failed:	0
	signal:  	-33 dBm
	current time:	1655310275763 ms
```

### Creating Network Namespaces

Next, create three network namespaces using the following commands:
```shell
$ sudo ip netns add ns0
$ sudo ip netns add ns1
$ sudo ip netns add ns2
````

Assign the three interfaces to separate network namespaces.
Please note that the `wiphy` is placed within the network namespace, and the interface associated with that wiphy will be contained within it.
```shell
$ sudo iw phy phy11 set netns name ns0
$ sudo iw phy phy12 set netns name ns1
$ sudo iw phy phy13 set netns name ns2
```

Then, bring up the three interfaces:
```shell
sudo ip netns exec ns0 ip link set owl0 up
sudo ip netns exec ns1 ip link set owl1 up
sudo ip netns exec ns2 ip link set owl2 up
```

Running `hostapd` based on the script `scripts/hostapd.conf`:
```shell
interface=owl0
driver=nl80211
ssid=TestAP
channel=6
```

Make sure to run `hostapd` in the network namespace where `owl0` is located.
Use the following command:
```shell	
$ sudo ip netns exec ns0 hostapd -B scripts/hostapd.conf
```

### Assigning IP Addresses to Each Interface

Now, assign an IP address to each interface using the following commands:
```shell
$ sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev owl0
$ sudo ip netns exec ns1 ip addr add 10.0.0.2/24 dev owl1
$ sudo ip netns exec ns2 ip addr add 10.0.0.3/24 dev owl2
```

### Testing Connectivity

Next, ping `owl2` (10.0.0.3) from `owl1` (10.0.0.2) using the following command:
```shell
$ sudo ip netns exec ns1 ping -c 1 10.0.0.3
```

You should expect the ping to fail between `owl1` and `owl2`, which is normal.
They have not connected to the AP (`owl0`) yet,
and STAs are not allowed to communicate with each other without the intervention of the AP.

Perform a scanning operation on `owl1` using the following command:
```shell
$ sudo ip netns exec ns1 iw dev owl1 scan
```

You should see output similar to the following:
```
BSS 00:6f:77:6c:30:00(on owl1)
	TSF: 1859697982 usec (0d, 00:30:59)
	freq: 2437
	beacon interval: 100 TUs
	capability: ESS (0x0001)
	signal: -43.00 dBm
	last seen: 0 ms ago
	SSID: TestAP
```

Perform the same operation for `owl2`.

Connect `owl1` and `owl2` to the AP `owl0` using the following commands:
```shell
$ sudo ip netns exec ns1 iw dev owl1 connect TestAP
$ sudo ip netns exec ns2 iw dev owl2 connect TestAP
```

### Validating the Connection

To validate the connection, use the following command:
```shell
$ sudo ip netns exec ns1 iw dev owl1 link
```

Reference output:
```shell
Connected to 00:6f:77:6c:30:00 (on owl1)
	SSID: TestAP
	freq: 2437
	RX: 0 bytes (0 packets)
	TX: 0 bytes (0 packets)
	signal: -31 dBm
```

Finally, we can do the ping test:
1. To perform a ping test between two STAs (`owl1` and `owl2`), use the following command:
```shell
$ sudo ip netns exec ns1 ping -c 4 10.0.0.3
```

You should see output similar to the following:
```
PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=0.188 ms
64 bytes from 10.0.0.3: icmp_seq=2 ttl=64 time=0.147 ms
64 bytes from 10.0.0.3: icmp_seq=3 ttl=64 time=0.082 ms
64 bytes from 10.0.0.3: icmp_seq=4 ttl=64 time=0.136 ms

--- 10.0.0.3 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3036ms
rtt min/avg/max/mdev = 0.082/0.138/0.188/0.037 ms
```

2. To perform a ping test between the AP (`owl0`) and a STA (`owl2`), execute the following command:
```shell
$ sudo ip netns exec ns2 ping -c 4 10.0.0.1
```

You should see output similar to the following:
```
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.342 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.054 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.106 ms
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=0.063 ms

--- 10.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3058ms
rtt min/avg/max/mdev = 0.054/0.141/0.342/0.117 ms
```

To perform all the operations mentioned above, you can simply run the test script `scripts/verify.sh`.

### Optional: Monitoring Wireless Device

If desired, you can use wireless device monitoring applications such as [wavemon](https://github.com/uoaerg/wavemon) to observe signal and noise levels,
packet statistics, device configuration, and network parameters of `vwifi`.
```shell
$ sudo apt install wavemon
```

<p align="center"><img src="assets/wavemon.png" alt="logo image" width=40%></p>

## License

`vwifi` is released under the MIT license. Use of this source code is governed
by a MIT-style license that can be found in the LICENSE file.

## Reference

* [mac80211_hwsim](https://www.kernel.org/doc/html/latest/networking/mac80211_hwsim/mac80211_hwsim.html): software simulator of 802.11 radio(s) for mac80211
* [Emulating WLAN in Linux - part I: the 802.11 stack](https://linuxembedded.fr/2020/05/emulating-wlan-in-linux-part-i-the-80211-stack)
* [Emulating WLAN in Linux - part II: mac80211_hwsim](https://linuxembedded.fr/2021/01/emulating-wlan-in-linux-part-ii-mac80211hwsim)
* [virt_wifi](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/virt_wifi.c): a completet virtual wireless driver that can be used as a wrapper around Ethernet.
* [vwifi](https://github.com/Raizo62/vwifi): simulate Wi-Fi (802.11) between Linux Virtual Machines.
