# vwifi: A Simple Virtual Wireless Driver for Linux

`vwifi` implements a minimal interface to achieve basic functionalities,
such as scanning dummy Wi-Fi networks, connecting, and disconnecting from them.
It is based on the [cfg80211 subsystem](https://www.kernel.org/doc/html/latest/driver-api/80211/cfg80211.html),
which works together with FullMAC drivers.
Currently, vwifi supports both Station Mode and Host AP Mode, and is well-equipped with WPA/WPA2 security facilities. This enables users to set up a wireless environment using vwifi, hostapd (in HostAP mode interface), and wpa_supplicant (in station mode interface).

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
phy#2
	Interface owl2
		ifindex 5
		wdev 0x200000001
		addr 00:6f:77:6c:32:00
		type managed
phy#1
	Interface owl1
		ifindex 4
		wdev 0x100000001
		addr 00:6f:77:6c:31:00
		type managed
phy#0
	Interface owl0
		ifindex 3
		wdev 0x1
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
Wiphy phy2
(... omit)
Wiphy phy1
(... omit)
Wiphy phy0
	wiphy index: 0
	max # scan SSIDs: 69
	max scan IEs length: 0 bytes
	max # sched scan SSIDs: 0
	max # match sets: 0
	Retry short limit: 7
	Retry long limit: 4
	Coverage class: 0 (up to 0m)
	Supported Ciphers:
		* WEP40 (00-0f-ac:1)
		* WEP104 (00-0f-ac:5)
		* TKIP (00-0f-ac:2)
		* CCMP-128 (00-0f-ac:4)
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
			* 6.0 Mbps
			* 9.0 Mbps
			* 12.0 Mbps
			* 18.0 Mbps
			* 24.0 Mbps
			* 36.0 Mbps
			* 48.0 Mbps
			* 54.0 Mbps
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
			* 2417 MHz [2] (20.0 dBm)
			* 2422 MHz [3] (20.0 dBm)
			* 2427 MHz [4] (20.0 dBm)
			* 2432 MHz [5] (20.0 dBm)
			* 2437 MHz [6] (20.0 dBm)
			* 2442 MHz [7] (20.0 dBm)
			* 2447 MHz [8] (20.0 dBm)
			* 2452 MHz [9] (20.0 dBm)
			* 2457 MHz [10] (20.0 dBm)
			* 2462 MHz [11] (20.0 dBm)
			* 2467 MHz [12] (20.0 dBm) (no IR)
			* 2472 MHz [13] (20.0 dBm) (no IR)
			* 2484 MHz [14] (20.0 dBm) (no IR)
	Supported commands:
		 * set_interface
		 * new_key
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
```

You can see the supported operating modes, supported ciphers, channels, bitrates, and supported commands in the output.

The "managed mode" in the Supported interface modes is identical to station mode.

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
$ sudo iw phy phy0 set netns name ns0
$ sudo iw phy phy1 set netns name ns1
$ sudo iw phy phy2 set netns name ns2
```

### Assigning IP Addresses to Each Interface

Now, assign an IP address to both interfaces using the following commands:
```shell
$ sudo ip netns exec ns0 ip addr add 10.0.0.1/24 dev owl0
$ sudo ip netns exec ns1 ip addr add 10.0.0.2/24 dev owl1
$ sudo ip netns exec ns2 ip addr add 10.0.0.3/24 dev owl2
```

### Running hostapd on the HostAP Mode Interface
Prepare the following script `hostapd.conf` (you can modify the script based on your needs):
```shell
interface=owl0
driver=nl80211
debug=1
ctrl_interface=/var/run/hostapd
ctrl_interface_group=wheel
channel=6
ssid=test
wpa=2
wpa_passphrase=12345678
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
```

Run `hostapd` on the interface `owl0`:
```shell	
$ sudo ip netns exec ns0 hostapd -i owl0 -B hostapd.conf
```

### Running wpa_supplicant on the Station Mode Interfaces
Prepare the following script `wpa_supplicant.conf` (you can modify the script based on your needs):
```shell
network={
    ssid="test"
    psk="12345678"
}
```

Then run the `wpa_supplicant` on the interface `ns1` and `ns2`:
```shell
sudo ip netns exec ns1 \
wpa_supplicant -i owl1 -B -c wpa_supplicant.conf
sudo ip netns exec ns2 \
wpa_supplicant -i owl2 -B -c wpa_supplicant.conf 
```

### Validating the Connection
To validate the connection, use the following command:
```shell
$ sudo ip netns exec ns1 iw dev owl1 link
```

The output might seem like this:
```
Connected to 00:6f:77:6c:30:00 (on owl1)
	SSID: test
	freq: 2437
	RX: 282 bytes (2 packets)
	TX: 248 bytes (2 packets)
	signal: -84 dBm
```

It shows that `owl1` has connected to the BSS with BSSID `00:6f:77:6c:30:00`, which is the MAC address of `owl0`.

You may also check the connection of `owl2` by slightly changing the command above.

On the other hand, we can validate all the stations connected to `owl0` by the following commands:
```shell
sudo ip netns exec ns0 iw dev owl0 station dump
```

The output may seem like this:
```shell
Station 00:6f:77:6c:31:00 (on owl0)
	inactive time:	5588 ms
	rx bytes:	5366
	rx packets:	65
	tx bytes:	1772
	tx packets:	18
	tx failed:	74
	signal:  	-57 dBm
	current time:	1689679337171 ms
Station 00:6f:77:6c:32:00 (on owl0)
	inactive time:	5588 ms
	rx bytes:	5366
	rx packets:	65
	tx bytes:	1772
	tx packets:	18
	tx failed:	74
	signal:  	-57 dBm
	current time:	1689679337171 ms
```
### Transmission/Receivement test
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
* [virt_wifi](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/virtual/virt_wifi.c): a complete virtual wireless driver that can be used as a wrapper around Ethernet.
* [vwifi](https://github.com/Raizo62/vwifi): simulate Wi-Fi (802.11) between Linux Virtual Machines.
