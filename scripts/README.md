# mac80211_hwsim demo
- Hostapd set up
```shell
sudo service network-manager stop

sudo modprobe -r mac80211_hwsim
sudo modprobe mac80211_hwsim radios=2
sudo hostapd hostapd_open.conf -i wlan0
sudo ip addr add 192.168.42.1/24 dev wlan0
```
- Station set up
```shell
sudo wpa_supplicant -Dnl80211 -iwlan1 -c wpa_supplicant.conf
```
- DHCP Setup
```shell
sudo dhcpd -cf dhcpd.conf wlan0
sudo dhclient -4 wlan1
```
## trace_cmd
```
trace-cmd record -p function -l '*80211*' iw dev wlan1 set channel 8
trace-cmd report
```
