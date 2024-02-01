#include <linux/etherdevice.h>
#include <linux/hashtable.h>
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/workqueue.h>
#include <net/cfg80211.h>
#include <uapi/linux/virtio_net.h>

#include <linux/netlink.h>
#include <net/sock.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("virtual cfg80211 driver");

#define NAME_PREFIX "vw"
#define NDEV_NAME NAME_PREFIX "%d"

#define VWIFI_WIPHY_NAME_LEN 12
#define VWIFI_WIPHY_PREFIX "vw_phy"

#define DOT11_MGMT_HDR_LEN 24      /* d11 management header len */
#define DOT11_BCN_PRB_FIXED_LEN 12 /* beacon/probe fixed length */

#define MAX_PROBED_SSIDS 69
#define IE_MAX_LEN 512

#define SCAN_TIMEOUT_MS 100 /*< millisecond */

/* Note: vwifi_cipher_suites is an array of int defining which cipher suites
 * are supported. A pointer to this array and the number of entries is passed
 * on to upper layers.
 */
static const u32 vwifi_cipher_suites[] = {
    WLAN_CIPHER_SUITE_WEP40,
    WLAN_CIPHER_SUITE_WEP104,
    WLAN_CIPHER_SUITE_TKIP,
    WLAN_CIPHER_SUITE_CCMP,
};

struct vwifi_packet {
    int datalen;
    u8 data[ETH_DATA_LEN];
    struct list_head list;
};

enum vwifi_state { VWIFI_READY, VWIFI_SHUTDOWN };

/* Context for the whole program, so there's only single vwifi_context
 * regardless of the number of virtual interfaces. Fields in the structure
 * are interface-independent.
 */
struct vwifi_context {
    /* We may not need this lock because vif_list would not change during
     * the whole lifetime.
     */
    struct mutex lock;
    enum vwifi_state state;    /**< indicate the program state */
    struct list_head vif_list; /**< maintaining all interfaces */
    struct list_head ap_list;  /**< maintaining multiple AP */
    char *blocklist;           /**< maintaining the blocklist */
};

static DEFINE_SPINLOCK(vif_list_lock);

/* SME stands for "station management entity" */
enum sme_state { SME_DISCONNECTED, SME_CONNECTING, SME_CONNECTED };

/* Each virtual interface contains a wiphy, vwifi_wiphy_counter is responsible
 * for recording the number of wiphy in vwifi.
 */
static atomic_t vwifi_wiphy_counter = ATOMIC_INIT(0);

/* Virtual interface pointed to by netdev_priv(). Fields in the structure are
 * interface-dependent. Every interface has its own vwifi_vif, regardless of the
 * interface mode (STA, AP, Ad-hoc...).
 */
struct vwifi_vif {
    struct wireless_dev wdev;
    struct net_device *ndev;
    struct net_device_stats stats;

    size_t ssid_len;
    /* Currently connected BSS id */
    u8 bssid[ETH_ALEN];
    u8 ssid[IEEE80211_MAX_SSID_LEN];

    struct list_head rx_queue; /**< Head of received packet queue */
    /* Store all vwifi_vif which is in the same BSS (AP will be the head). */
    struct list_head bss_list;
    /* List entry for maintaining all vwifi_vif, which can be accessed via
     * vwifi->vif_list.
     */
    struct list_head list;

    struct mutex lock;

    /* Split logic for STA and AP mode */
    union {
        /* Structure for STA mode */
        struct {
            /* For the case the STA is going to roam to another BSS */
            u8 req_ssid[IEEE80211_MAX_SSID_LEN];

            struct cfg80211_scan_request *scan_request;
            enum sme_state sme_state; /* connection information */
            /* last connection time to a AP (in jiffies) */
            unsigned long conn_time;
            unsigned long active_time; /**< last tx/rx time (in jiffies) */
            u16 disconnect_reason_code;

            struct timer_list scan_timeout;
            struct work_struct ws_connect, ws_disconnect;
            struct work_struct ws_scan, ws_scan_timeout;

            /* For quickly finding the AP */
            struct vwifi_vif *ap;
        };
        /* Structure for AP mode */
        struct {
            bool ap_enabled;
            bool privacy;
            /* List node for storing AP (vwifi->ap_list is the head),
             * this field is for interface in AP mode.
             */
            struct list_head ap_list;
            /* beacon interval in us */
            u64 beacon_int;
            struct hrtimer beacon_timer;
            struct ieee80211_channel *channel;
            enum nl80211_chan_width bw;
        };
    };

    struct timer_list scan_complete;
    u8 req_bssid[ETH_ALEN];
    u32 beacon_ie_len;
    u8 beacon_ie[IE_MAX_LEN];

    /* Store all STAs in the same BSS, right now only used when virtio enabled
     */
    DECLARE_HASHTABLE(bss_sta_table, 4);
    /* Don't share the vif->lock because updating bss_sta_table may take a long
     * time */
    struct mutex bss_sta_table_lock;
    u32 bss_sta_table_entry_num;

    /* Packet virtio header size */
    u8 vnet_hdr_len;
};

static int station = 2;
module_param(station, int, 0444);
MODULE_PARM_DESC(station, "Number of virtual interfaces running in STA mode.");

/* Global context */
static struct vwifi_context *vwifi = NULL;

/* Blocklist content */
#define MAX_BLACKLIST_SIZE 1024

static struct sock *nl_sk = NULL;

static int blocklist_check(char *dest, char *source)
{
    if (!vwifi->blocklist || !*(vwifi->blocklist))
        return 0;

    char *user_input =
        kmalloc(sizeof(char) * (strlen(vwifi->blocklist) + 1), GFP_KERNEL);
    strncpy(user_input, vwifi->blocklist, strlen(vwifi->blocklist));

    char *token = strsep(&user_input, "\n");
    while (token) {
        char *blacklist_dest = strsep(&token, " ");
        strsep(&token, " ");
        char *blacklist_source = token;
        if (!strcmp(dest, blacklist_dest) &&
            !strcmp(source, blacklist_source)) {
            kfree(user_input);
            return 1;
        }
        token = strsep(&user_input, "\n");
    }
    kfree(user_input);

    return 0;
}

static void blocklist_load(char *blist)
{
    if (!vwifi->blocklist) {
        pr_info("vwifi->blocklist have to be kmalloc first\n");
        return;
    }
    memset(vwifi->blocklist, '\0',
           MAX_BLACKLIST_SIZE); /* clear the blocklist */
    strncpy(vwifi->blocklist, blist, strlen(blist));
}

static void blocklist_nl_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh; /* netlink message header */
    int pid;
    struct sk_buff *skb_out;
    char *msg = "vwifi has received your blocklist";
    int msg_size = strlen(msg);

    nlh = (struct nlmsghdr *) skb->data;

    blocklist_load((char *) nlmsg_data(nlh));

    /* pid of sending process */
    pid = nlh->nlmsg_pid;

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        pr_info("netlink: Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* unicast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    if (nlmsg_unicast(nl_sk, skb_out, pid) < 0)
        pr_info("netlink: Error while sending back to user\n");
}

static struct netlink_kernel_cfg nl_config = {
    .input = blocklist_nl_recv,
};

/**
 * enum virtio_vqs - queues for virtio frame transmission and receivement
 *
 * For virtio-net device, We expect 1 RX virtqueue followed by 1 TX virtqueue,
 * followed by possible N-1 RX/TX queue pairs used in multiqueue mode, followed
 * by possible control vq. For now, we don't support multiqueue mode virtio-net
 * device and control vq as well, so there are only 1 RX vq and 1 TX vq.
 *
 * @VWIFI_VQ_TX: send frames to external entity
 * @VWIFI_VQ_RX: receive frames
 * @VWIFI_NUM_VQS: enum limit
 */
enum {
    VWIFI_VQ_RX,
    VWIFI_VQ_TX,
    VWIFI_NUM_VQS,
};

static struct virtqueue *vwifi_vqs[VWIFI_NUM_VQS];
static bool vwifi_virtio_enabled;

static DEFINE_SPINLOCK(vwifi_virtio_lock);

static void vwifi_virtio_rx_work(struct work_struct *work);
static DECLARE_WORK(vwifi_virtio_rx, vwifi_virtio_rx_work);

/**
 * enum VWIFI_VIRTIO_PACKET_TYPE - non-standard management frame type for VWIFI
 *
 * Most of these types are inspired by IEEE 802.11 management frame, with
 * little modifications since we are sending Ethernet frames. And note that
 * we send these management frame with the Ethertype/length field being
 * length (i.e. 802.3 frames), so we can distinguish it from a data frame
 * (Ethernet II).
 *
 * See struct vwifi_virtio_header for the VWIFI management frame structures.
 * For future modifications, please ensure that the VWIFI management frame
 * contains the needed informations consumed by cfg80211/nl80211.
 *
 * For the reason why we have the VWIFI_STA_ENTRY_REQUEST and
 * VWIFI_STA_ENTRY_RESPONSE: There are three to four addresses in a normal
 * 802.11 data frame, an STA can recognize whether the frame is for our BSS or
 * not by looking at a specific address (ToDS/FromDS in the frame control
 * determines the address layout). However, we get Ethernet frames from network
 * stack (cfg80211 doesn't implement the 802.11 data TX path), and we don't
 * convert it to IEEE 802.11 frame since we pretend ourself (vwifi) to be a
 * virtio-net driver and would like to pass Ethernet frame to virtio-net device.
 * So the VWIFI_STA_ENTRY_REQUEST and VWIFI_STA_ENTRY_RESPONSE comes to the
 * rescue. After an STA has connected to an an AP, the STA will request the AP
 * about the informations (currently only MAC address) of other STAs in the same
 * BSS, and then store them in an STA entry table. Whenever an STA receives a
 * data frame, it checks whether the source address in the Ethernet header is in
 * its STA entry table, and only if the condition is true, the STA pass the
 * frame into network stack.
 *
 * @VWIFI_SCAN_REQUEST: active scan, request AP to reveal its informations.
 * @VWIFI_SCAN_RESPONSE: AP informs its informations to STA.
 * @VWIFI_CONNECT_REQUEST: request a connection to an AP.
 * @VWIFI_CONNECT_RESPONSE: inform the STA about the success of the connection,
 *                          and AP will call cfg80211_add_sta() to inform
 * hostapd. If the AP runs with WPA/WPA2 (STA knows it since the beacon_ies
 * contains WPA/RSN IE), hostapd will then fire the 4-way handshake to change
 * keys with the STA. Only until the 4-way handshake is done (we learn it from
 * cfg80211->change_station()), the STA can start to exchange packets with other
 * STAs in the same BSS.
 * @VWIFI_DISCONNECT: inform the disconnection. This type can be sent by STA or
 * AP.
 * @VWIFI_STA_ENTRY_REQUEST: STA requests the connected AP for the STA entries
 * in the same BSS.
 * @VWIFI_STA_ENTRY_RESPONSE: There are two case:
 *                            1. AP reply the STA's request about the STA
 * entries and the STA entries include all the STAs in the BSS.
 *                            2. An unsolicited VWIFI_STA_ENTRY_RESPONSE will be
 * broadcasted by AP when an STA is connected or disconnected, so other STAs in
 * the same BSS can update their STA entry table.
 */
enum VWIFI_VIRTIO_PACKET_TYPE {
    VWIFI_SCAN_REQUEST,
    VWIFI_SCAN_RESPONSE,
    VWIFI_CONNECT_REQUEST,
    VWIFI_CONNECT_RESPONSE,
    VWIFI_DISCONNECT,
    VWIFI_STA_ENTRY_REQUEST,
    VWIFI_STA_ENTRY_RESPONSE,
};

struct vwifi_virtio_header {
    __le16 type;
#define VWIFI_VIRTIO_HEADER_TYPE_BYTE 2
    union {
        struct vwifi_virtio_scan_req {
            __le32 ssid_len;
            u8 ssid[IEEE80211_MAX_SSID_LEN];
        } __packed scan_req;
        struct vwifi_virtio_scan_resp {
            u8 bssid[ETH_ALEN];
            __le64 timestamp;
            __le16 beacon_int;
            __le16 capab_info;
            __le32 ssid_len;
            u8 ssid[IEEE80211_MAX_SSID_LEN];
            __le32 channel; /* center frquency */
            __le32 beacon_ies_len;
            u8 beacon_ies[];
        } __packed scan_resp;
        struct vwifi_virtio_conn_req {
            u8 bssid[ETH_ALEN];
            __le32 ssid_len;
            u8 ssid[IEEE80211_MAX_SSID_LEN];
        } __packed connect_req;
        struct vwifi_virtio_conn_resp {
            __le16 status_code;
            __le16 capab_info;
        } __packed connect_resp;
        struct vwifi_virtio_disconn {
            u8 bssid[ETH_ALEN];
            __le16 reason_code;
        } __packed disconn;
        struct vwifi_virtio_sta_entry_resp {
            u8 bssid[ETH_ALEN];
            __le16 cmd;
            __le32 count;
            u8 macs[ETH_ALEN];
        } __packed sta_entry_resp;
    } u;
} __packed;

enum VWIFI_STA_ENTRY_CMD {
    VWIFI_STA_ENTRY_ADD,
    VWIFI_STA_ENTRY_ADD_ALL,
    VWIFI_STA_ENTRY_DEL,
};

struct bss_sta_entry {
    struct hlist_node node;
    u8 mac[ETH_ALEN];
};

/* helper function to retrieve vif from net_device */
static inline struct vwifi_vif *ndev_get_vwifi_vif(struct net_device *ndev)
{
    return (struct vwifi_vif *) netdev_priv(ndev);
}

/* helper function to retrieve vif from wireless_dev */
static inline struct vwifi_vif *wdev_get_vwifi_vif(struct wireless_dev *wdev)
{
    return container_of(wdev, struct vwifi_vif, wdev);
}

static inline u32 vwifi_mac_to_32(const u8 *mac)
{
    u32 h = 3323198485U;
    for (int i = 0; i < ETH_ALEN; i++) {
        h ^= *(mac + i);
        h *= 0x5bd1e995;
        h ^= h >> 15;
    }
    return h;
}

#define SIN_S3_MIN (-(1 << 12))
#define SIN_S3_MAX (1 << 12)

/* A sine approximation via a third-order approx.
 * Refer to https://www.coranac.com/2009/07/sines for details about the
 * algorithm. Some parameters have been adjusted to increase the frequency
 * of the sine function.
 * Note: __sin_s3() is intended for internal use by rand_int_smooth() and
 * should not be called elsewhere.
 *
 * @x: seed to generate third-order sine value
 * @return: signed 32-bit integer ranging from SIN_S3_MIN to SIN_S3_MAX
 */
static inline s32 __sin_s3(s32 x)
{
    /* S(x) = (x * (3 * 2^p - (x * x)/2^r)) / 2^s
     * @n: the angle scale
     * @A: the amplitude
     * @p: keep the multiplication from overflowing
     */
    const int32_t n = 6, A = 12, p = 10, r = 2 * n - p, s = n + p + 1 - A;

    x = x << (30 - n);

    if ((x ^ (x << 1)) < 0)
        x = (1 << 31) - x;

    x = x >> (30 - n);
    return (x * ((3 << p) - ((x * x) >> r))) >> s;
}

/* Generate a signed 32-bit integer by feeding the seed into __sin_s3().
 * The distribution of (seed, rand_int_smooth()) is closer to a sine function
 * when plotted.
 */
static inline s32 rand_int_smooth(s32 low, s32 up, s32 seed)
{
    s32 result = __sin_s3(seed) - SIN_S3_MIN;
    result = (result * (up - low)) / (SIN_S3_MAX - SIN_S3_MIN);
    result += low;
    return result;
}

/* Helper function that prepares a structure with self-defined BSS information
 * and "informs" the kernel about the "new" BSS. Most of the code is copied from
 * the upcoming inform_dummy_bss function.
 */
static void inform_bss(struct vwifi_vif *vif)
{
    struct vwifi_vif *ap;

    list_for_each_entry (ap, &vwifi->ap_list, ap_list) {
        struct cfg80211_bss *bss = NULL;
        struct cfg80211_inform_bss data = {
            /* the only channel */
            .chan = &ap->wdev.wiphy->bands[NL80211_BAND_2GHZ]->channels[0],
            .scan_width = NL80211_BSS_CHAN_WIDTH_20,
            .signal = DBM_TO_MBM(rand_int_smooth(-100, -30, jiffies)),
        };
        int capability = WLAN_CAPABILITY_ESS;

        if (ap->privacy)
            capability |= WLAN_CAPABILITY_PRIVACY;

        pr_info("vwifi: %s performs scan, found %s (SSID: %s, BSSID: %pM)\n",
                vif->ndev->name, ap->ndev->name, ap->ssid, ap->bssid);
        pr_info("cap = %d, beacon_ie_len = %d\n", capability,
                ap->beacon_ie_len);

        /* Using the CLOCK_BOOTTIME clock, which remains unaffected by changes
         * in the system time-of-day clock and includes any time that the
         * system is suspended.
         * This clock is suitable for synchronizing the machines in the BSS
         * using tsf.
         */
        u64 tsf = div_u64(ktime_get_boottime_ns(), 1000);

        /* It is possible to use cfg80211_inform_bss() instead. */
        bss = cfg80211_inform_bss_data(
            vif->wdev.wiphy, &data, CFG80211_BSS_FTYPE_UNKNOWN, ap->bssid, tsf,
            capability, 100, ap->beacon_ie, ap->beacon_ie_len, GFP_KERNEL);

        /* cfg80211_inform_bss_data() returns cfg80211_bss structure reference
         * counter of which should be decremented if it is unused.
         */
        cfg80211_put_bss(vif->wdev.wiphy, bss);
    }
}

static void vwifi_beacon_inform_bss(struct vwifi_vif *ap,
                                    struct vwifi_vif *sta,
                                    struct cfg80211_inform_bss *bss_meta,
                                    int capability,
                                    u64 tsf)
{
    struct cfg80211_bss *bss = NULL;
    bss_meta->signal = DBM_TO_MBM(rand_int_smooth(-100, -30, jiffies));

    /* It is possible to use cfg80211_inform_bss() instead. */
    bss = cfg80211_inform_bss_data(sta->wdev.wiphy, bss_meta,
                                   CFG80211_BSS_FTYPE_BEACON, ap->bssid, tsf,
                                   capability, ap->beacon_int, ap->beacon_ie,
                                   ap->beacon_ie_len, GFP_KERNEL);

    /* cfg80211_inform_bss_data() returns cfg80211_bss structure reference
     * counter of which should be decremented if it is unused.
     */
    if (bss)
        cfg80211_put_bss(sta->wdev.wiphy, bss);
}

/* The callback function of the beacon timer prepares a structure with
 * custom BSS information and "notifies" the core about the "new"
 * BSS information.
 */
static enum hrtimer_restart vwifi_beacon(struct hrtimer *timer)
{
    struct vwifi_vif *vif = container_of(timer, struct vwifi_vif, beacon_timer);

    if (vif->wdev.iftype != NL80211_IFTYPE_AP &&
        vif->wdev.iftype != NL80211_IFTYPE_MESH_POINT &&
        vif->wdev.iftype != NL80211_IFTYPE_ADHOC &&
        vif->wdev.iftype != NL80211_IFTYPE_OCB)
        return HRTIMER_NORESTART;

    u64 timestamp = div_u64(ktime_get_boottime_ns(), 1000);

    struct cfg80211_inform_bss bss_meta = {
        .boottime_ns = ktime_get_boottime_ns(),
        .chan = vif->channel,
    };

    switch (vif->bw) {
    case NL80211_CHAN_WIDTH_5:
        bss_meta.scan_width = NL80211_BSS_CHAN_WIDTH_5;
        break;
    case NL80211_CHAN_WIDTH_10:
        bss_meta.scan_width = NL80211_BSS_CHAN_WIDTH_10;
        break;
    default:
        bss_meta.scan_width = NL80211_BSS_CHAN_WIDTH_20;
        break;
    }

    int capability = WLAN_CAPABILITY_ESS;

    if (vif->privacy)
        capability |= WLAN_CAPABILITY_PRIVACY;

    spin_lock(&vif_list_lock);
    struct vwifi_vif *sta;
    list_for_each_entry (sta, &vwifi->vif_list, list) {
        if (sta->wdev.iftype != NL80211_IFTYPE_STATION)
            continue;

        vwifi_beacon_inform_bss(vif, sta, &bss_meta, capability, timestamp);
    }
    spin_unlock(&vif_list_lock);

    /* beacon at next TBTT */
    u64 tsf, until_tbtt;
    tsf = ktime_to_us(ktime_get_real());
    u32 bcn_int = vif->beacon_int;
    until_tbtt = bcn_int - do_div(tsf, bcn_int);
    hrtimer_forward_now(&vif->beacon_timer,
                        ns_to_ktime(until_tbtt * NSEC_PER_USEC));

    return HRTIMER_RESTART;
}

static void vwifi_virtio_fill_vq(struct virtqueue *vq, u8 vnet_hdr_len);

static int vwifi_ndo_open(struct net_device *dev)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);

    netif_start_queue(dev);

    vwifi_virtio_fill_vq(vwifi_vqs[VWIFI_VQ_RX], vif->vnet_hdr_len);

    return 0;
}

static int vwifi_ndo_stop(struct net_device *dev)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);
    struct vwifi_packet *pkt, *is = NULL;
    list_for_each_entry_safe (pkt, is, &vif->rx_queue, list) {
        list_del(&pkt->list);
        kfree(pkt);
    }
    netif_stop_queue(dev);
    return 0;
}

static struct net_device_stats *vwifi_ndo_get_stats(struct net_device *dev)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);
    return &vif->stats;
}

static netdev_tx_t vwifi_ndo_start_xmit(struct sk_buff *skb,
                                        struct net_device *dev);

/* Receive a packet: retrieve, encapsulate it in an skb, and perform the
 * following operations based on the interface mode:
 *   - STA mode: Pass the skb to the upper level (protocol stack).
 *   - AP mode: Perform the following operations based on the packet type:
 *     1. Unicast: If the skb is intended for another STA, pass it to that
 *        STA and do not pass it to the protocol stack. If the skb is intended
 *        for the AP itself, pass it to the protocol stack.
 *     2. Broadcast: Pass the skb to all other STAs except the source STA, and
 *        then pass it to the protocol stack.
 *     3. Multicast: Perform the same operations as for broadcast.
 */
static void vwifi_rx(struct net_device *dev)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);
    /* socket buffer will be sended to protocol stack */
    struct sk_buff *skb;
    /* socket buffer will be transmitted to another STA */
    struct sk_buff *skb1 = NULL;
    struct vwifi_packet *pkt;

    if (list_empty(&vif->rx_queue)) {
        pr_info("vwifi rx: No packet in rx_queue\n");
        return;
    }

    if (mutex_lock_interruptible(&vif->lock))
        goto pkt_free;

    pkt = list_first_entry(&vif->rx_queue, struct vwifi_packet, list);

    vif->stats.rx_packets++;
    vif->stats.rx_bytes += pkt->datalen;
    vif->active_time = jiffies;

    mutex_unlock(&vif->lock);

    /* Put raw packet into socket buffer */
    skb = dev_alloc_skb(pkt->datalen + 2);
    if (!skb) {
        pr_info("vwifi rx: low on mem - packet dropped\n");
        vif->stats.rx_dropped++;
        goto pkt_free;
    }
    skb_reserve(skb, 2); /* align IP address on 16B boundary */
    memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

    list_del(&pkt->list);
    kfree(pkt);

    if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        struct ethhdr *eth_hdr = (struct ethhdr *) skb->data;

        /* When receiving a multicast/broadcast packet, it is sent to every
         * STA except the source STA, and then passed to the protocol stack.
         */
        if (is_multicast_ether_addr(eth_hdr->h_dest)) {
            pr_info("vwifi: is_multicast_ether_addr\n");
            skb1 = skb_copy(skb, GFP_KERNEL);
        }
        /* Receiving a unicast packet */
        else {
            /* The packet is not intended for the AP itself. Instead, it is
             * sent to the destination STA and not passed to the protocol stack.
             */
            if (!ether_addr_equal(eth_hdr->h_dest, vif->ndev->dev_addr)) {
                skb1 = skb;
                skb = NULL;
            }
        }

        if (skb1) {
            pr_info("vwifi: AP %s relay:\n", vif->ndev->name);
            vwifi_ndo_start_xmit(skb1, vif->ndev);
        }

        /* Nothing to pass to protocol stack */
        if (!skb)
            return;
    }

    /* Pass the skb to protocol stack */
    skb->dev = dev;
    skb->protocol = eth_type_trans(skb, dev);
    skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
    netif_rx_ni(skb);
#else
    netif_rx(skb);
#endif

    return;

pkt_free:
    list_del(&pkt->list);
    kfree(pkt);
}

static int __vwifi_ndo_start_xmit(struct vwifi_vif *vif,
                                  struct vwifi_vif *dest_vif,
                                  struct sk_buff *skb)
{
    struct vwifi_packet *pkt = NULL;
    struct ethhdr *eth_hdr = (struct ethhdr *) skb->data;
    int datalen;

    if (vif->wdev.iftype == NL80211_IFTYPE_STATION) {
        pr_info("vwifi: STA %s (%pM) send packet to AP %s (%pM)\n",
                vif->ndev->name, eth_hdr->h_source, dest_vif->ndev->name,
                eth_hdr->h_dest);
    } else if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        pr_info("vwifi: AP %s (%pM) send packet to STA %s (%pM)\n",
                vif->ndev->name, eth_hdr->h_source, dest_vif->ndev->name,
                eth_hdr->h_dest);
    }

    pkt = kmalloc(sizeof(struct vwifi_packet), GFP_KERNEL);
    if (!pkt) {
        pr_info("Ran out of memory allocating packet pool\n");
        return NETDEV_TX_OK;
    }
    datalen = skb->len;
    memcpy(pkt->data, skb->data, datalen);
    pkt->datalen = datalen;

    /* enqueue packet to destination vif's rx_queue */
    if (mutex_lock_interruptible(&dest_vif->lock))
        goto error_before_rx_queue;

    list_add_tail(&pkt->list, &dest_vif->rx_queue);

    mutex_unlock(&dest_vif->lock);

    if (mutex_lock_interruptible(&vif->lock))
        goto erorr_after_rx_queue;

    /* Update interface statistics */
    vif->stats.tx_packets++;
    vif->stats.tx_bytes += datalen;
    vif->active_time = jiffies;

    mutex_unlock(&vif->lock);

    if (dest_vif->wdev.iftype == NL80211_IFTYPE_STATION) {
        pr_info("vwifi: STA %s (%pM) receive packet from AP %s (%pM)\n",
                dest_vif->ndev->name, eth_hdr->h_dest, vif->ndev->name,
                eth_hdr->h_source);
    } else if (dest_vif->wdev.iftype == NL80211_IFTYPE_AP) {
        pr_info("vwifi: AP %s (%pM) receive packet from STA %s (%pM)\n",
                dest_vif->ndev->name, eth_hdr->h_dest, vif->ndev->name,
                eth_hdr->h_source);
    }

    /* Directly send to rx_queue, simulate the rx interrupt */
    vwifi_rx(dest_vif->ndev);

    return datalen;

erorr_after_rx_queue:
    list_del(&pkt->list);
error_before_rx_queue:
    kfree(pkt);
    return 0;
}

static netdev_tx_t vwifi_virtio_tx(struct vwifi_vif *vif, struct sk_buff *skb);

/* Network packet transmit.
 * Callback called by the kernel when packets need to be sent.
 */
static netdev_tx_t vwifi_ndo_start_xmit(struct sk_buff *skb,
                                        struct net_device *dev)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);
    struct vwifi_vif *dest_vif = NULL;
    struct ethhdr *eth_hdr = (struct ethhdr *) skb->data;
    unsigned long flags;
    int err;
    int count = 0;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);

    if (vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        err = vwifi_virtio_tx(vif, skb);
        return err;
    }

    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    /* TX by interface of STA mode */
    if (vif->wdev.iftype == NL80211_IFTYPE_STATION) {
        if (vif->ap && vif->ap->ap_enabled) {
            dest_vif = vif->ap;

            if (__vwifi_ndo_start_xmit(vif, dest_vif, skb))
                count++;
        }
    }
    /* TX by interface of AP mode */
    else if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        /* Find the source interface */
        struct vwifi_vif *src_vif;
        list_for_each_entry (src_vif, &vif->bss_list, bss_list) {
            if (ether_addr_equal(eth_hdr->h_source, src_vif->ndev->dev_addr))
                break;
        }

        /* Check if the packet is broadcasting */
        if (is_broadcast_ether_addr(eth_hdr->h_dest)) {
            list_for_each_entry (dest_vif, &vif->bss_list, bss_list) {
                /* Don't send broadcast packet back to the source interface.
                 */
                if (ether_addr_equal(eth_hdr->h_source,
                                     dest_vif->ndev->dev_addr))
                    continue;

                /* Don't send packet from dest_vif's blocklist */
                if (blocklist_check(dest_vif->ndev->name, src_vif->ndev->name))
                    continue;

                if (__vwifi_ndo_start_xmit(vif, dest_vif, skb))
                    count++;
            }
        }
        /* The packet is unicasting */
        else {
            list_for_each_entry (dest_vif, &vif->bss_list, bss_list) {
                if (ether_addr_equal(eth_hdr->h_dest,
                                     dest_vif->ndev->dev_addr)) {
                    if (!blocklist_check(dest_vif->ndev->name,
                                         src_vif->ndev->name) &&
                        __vwifi_ndo_start_xmit(vif, dest_vif, skb))
                        count++;
                    break;
                }
            }
        }
    }

    if (!count)
        vif->stats.tx_dropped++;

    /* Don't forget to cleanup skb, as its ownership moved to xmit callback. */
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

/* Structure of functions for network devices.
 * It should have at least ndo_start_xmit functions called for packet to be
 * sent.
 */
static struct net_device_ops vwifi_ndev_ops = {
    .ndo_open = vwifi_ndo_open,
    .ndo_stop = vwifi_ndo_stop,
    .ndo_start_xmit = vwifi_ndo_start_xmit,
    .ndo_get_stats = vwifi_ndo_get_stats,
};

/* Inform the "dummy" BSS to kernel and call cfg80211_scan_done() to finish
 * scan.
 */
static void vwifi_scan_timeout_work(struct work_struct *w)
{
    struct vwifi_vif *vif = container_of(w, struct vwifi_vif, ws_scan_timeout);
    struct cfg80211_scan_info info = {
        /* if scan was aborted by user (calling cfg80211_ops->abort_scan) or by
         * any driver/hardware issue - field should be set to "true"
         */
        .aborted = false,
    };

    /* inform with dummy BSS */
    inform_bss(vif);

    if (mutex_lock_interruptible(&vif->lock))
        return;

    /* finish scan */
    cfg80211_scan_done(vif->scan_request, &info);

    vif->scan_request = NULL;

    mutex_unlock(&vif->lock);
}

/* Callback called when the scan timer timeouts. This function just schedules
 * the timeout work and offloads the job of informing "dummy" BSS to kernel
 * onto it.
 */
static void vwifi_scan_timeout(struct timer_list *t)
{
    struct vwifi_vif *vif = container_of(t, struct vwifi_vif, scan_timeout);

    if (vif->scan_request)
        schedule_work(&vif->ws_scan_timeout);
}

static void vwifi_virtio_scan_request(struct vwifi_vif *vif);

/* Scan routine. It simulates a fake BSS scan (in fact, it does nothing) and
 * sets a scan timer to start from then. Once the timer timeouts, the timeout
 * routine vwifi_scan_timeout() will be invoked. This routine schedules a
 * timeout work that informs the kernel about the "dummy" BSS and completes the
 * scan.
 */
static void vwifi_scan_routine(struct work_struct *w)
{
    struct vwifi_vif *vif = container_of(w, struct vwifi_vif, ws_scan);
    unsigned long flags;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);

    if (vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        vwifi_virtio_scan_request(vif);
        return;
    }

    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    /* In a real-world driver, BSS scanning would occur here. However, in the
     * case of viwifi, scanning is not performed because dummy BSS entries are
     * already stored in the SSID hash table. Instead, a scan timeout is set
     * after a specific number of jiffies. The timeout worker informs the
     * kernel about the "dummy" BSS and calls cfg80211_scan_done() to complete
     * the scan.
     */
    mod_timer(&vif->scan_timeout, jiffies + msecs_to_jiffies(SCAN_TIMEOUT_MS));
}

static void vwifi_virtio_connect_request(struct vwifi_vif *vif);

static void vwifi_connect_routine(struct work_struct *w)
{
    struct vwifi_vif *vif = container_of(w, struct vwifi_vif, ws_connect);
    struct vwifi_vif *ap = NULL;
    struct station_info *sinfo;
    unsigned long flags;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);

    if (vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        vwifi_virtio_connect_request(vif);
        return;
    }

    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    if (mutex_lock_interruptible(&vif->lock))
        return;

    /* Finding the AP by request SSID */
    list_for_each_entry (ap, &vwifi->ap_list, ap_list) {
        if (!memcmp(ap->ssid, vif->req_ssid, ap->ssid_len)) {
            pr_info("vwifi: %s is connected to AP %s (SSID: %s, BSSID: %pM)\n",
                    vif->ndev->name, ap->ndev->name, ap->ssid, ap->bssid);

            if (mutex_lock_interruptible(&ap->lock))
                return;

            /* AP connection part */
            sinfo = kmalloc(sizeof(struct station_info), GFP_KERNEL);
            if (!sinfo)
                return;

            /* It is safe that we fake the association request IEs
             * by beacon IEs, since they both possibly have the WPA/RSN IE
             * which is what the upper user-space program (e.g. hostapd)
             * cares about.
             */
            sinfo->assoc_req_ies = ap->beacon_ie;
            sinfo->assoc_req_ies_len = ap->beacon_ie_len;

            list_add_tail(&vif->bss_list, &ap->bss_list);

            /* nl80211 will inform the user-space program (e.g. hostapd)
             * about the newly-associated station via generic netlink
             * command NL80211_CMD_NEW_STATION for latter processing
             * (e.g. 4-way handshake).
             */
            cfg80211_new_sta(ap->ndev, vif->ndev->dev_addr, sinfo, GFP_KERNEL);

            mutex_unlock(&ap->lock);

            /* STA connection part */
            cfg80211_connect_result(vif->ndev, ap->bssid, NULL, 0, NULL, 0,
                                    WLAN_STATUS_SUCCESS, GFP_KERNEL);
            memcpy(vif->ssid, ap->ssid, ap->ssid_len);
            memcpy(vif->bssid, ap->bssid, ETH_ALEN);
            vif->sme_state = SME_CONNECTED;
            vif->conn_time = jiffies;
            vif->ap = ap;

            mutex_unlock(&vif->lock);

            kfree(sinfo);

            return;
        }
    }

    /* SSID not found */
    pr_info("vwifi: SSID %s not found\n", vif->req_ssid);

    cfg80211_connect_timeout(vif->ndev, NULL, NULL, 0, GFP_KERNEL,
                             NL80211_TIMEOUT_SCAN);
    vif->sme_state = SME_DISCONNECTED;
    mutex_unlock(&vif->lock);
}

static void vwifi_virtio_disconnect(struct vwifi_vif *vif);

/* Invoke cfg80211_disconnected() that informs the kernel that disconnect is
 * complete. Overall disconnect may call cfg80211_connect_timeout() if
 * disconnect interrupting connection routine, but for this module let's keep
 * it simple as possible. This routine is called through workqueue, when the
 * kernel asks to disconnect through cfg80211_ops.
 */
static void vwifi_disconnect_routine(struct work_struct *w)
{
    struct vwifi_vif *vif = container_of(w, struct vwifi_vif, ws_disconnect);
    unsigned long flags;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);

    if (vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        vwifi_virtio_disconnect(vif);
        return;
    }

    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    pr_info("vwifi: %s disconnected from AP %s\n", vif->ndev->name,
            vif->ap->ndev->name);

    if (mutex_lock_interruptible(&vif->lock))
        return;

    /* STA cleanup stuff */
    cfg80211_disconnected(vif->ndev, vif->disconnect_reason_code, NULL, 0, true,
                          GFP_KERNEL);

    vif->disconnect_reason_code = 0;
    vif->sme_state = SME_DISCONNECTED;

    /* AP cleanup stuff */
    if (vwifi->state != VWIFI_SHUTDOWN) {
        if (mutex_lock_interruptible(&vif->ap->lock)) {
            mutex_unlock(&vif->lock);
            return;
        }

        if (vif->ap->ap_enabled && !list_empty(&vif->bss_list)) {
            cfg80211_del_sta(vif->ap->ndev, vif->ndev->dev_addr, GFP_KERNEL);
            list_del(&vif->bss_list);
        }

        mutex_unlock(&vif->ap->lock);

        vif->ap = NULL;
    }

    mutex_unlock(&vif->lock);
}

/* callback called by the kernel when user decided to scan.
 * This callback should initiate scan routine(through work_struct) and exit with
 * 0 if everything is ok.
 */
static int vwifi_scan(struct wiphy *wiphy,
                      struct cfg80211_scan_request *request)
{
    struct vwifi_vif *vif = wdev_get_vwifi_vif(request->wdev);

    if (mutex_lock_interruptible(&vif->lock))
        return -ERESTARTSYS;

    if (vif->scan_request) {
        mutex_unlock(&vif->lock);
        return -EBUSY;
    }

    if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        mutex_unlock(&vif->lock);
        return -EPERM;
    }
    vif->scan_request = request;

    mutex_unlock(&vif->lock);

    if (!schedule_work(&vif->ws_scan))
        return -EBUSY;
    return 0;
}

/* callback called by the kernel when there is need to "connect" to some
 * network. It initializes connection routine through work_struct and exits
 * with 0 if everything is ok. connect routine should be finished with
 * cfg80211_connect_bss()/cfg80211_connect_result()/cfg80211_connect_done() or
 * cfg80211_connect_timeout().
 */
static int vwifi_connect(struct wiphy *wiphy,
                         struct net_device *dev,
                         struct cfg80211_connect_params *sme)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);

    if (mutex_lock_interruptible(&vif->lock))
        return -ERESTARTSYS;

    if (vif->sme_state != SME_DISCONNECTED) {
        mutex_unlock(&vif->lock);
        return -EBUSY;
    }

    if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        mutex_unlock(&vif->lock);
        return -EPERM;
    }

    vif->sme_state = SME_CONNECTING;
    vif->ssid_len = sme->ssid_len;
    memcpy(vif->req_ssid, sme->ssid, sme->ssid_len);
    if (sme->bssid)
        memcpy(vif->req_bssid, sme->bssid, ETH_ALEN);
    mutex_unlock(&vif->lock);

    if (!schedule_work(&vif->ws_connect))
        return -EBUSY;
    return 0;
}

/* callback called by the kernel when there is need to "disconnect" from
 * currently connected network. It initializes disconnect routine through
 * work_struct and exits with 0 if everything ok. disconnect routine should
 * call cfg80211_disconnected() to inform the kernel that disconnection is
 * complete.
 */
static int vwifi_disconnect(struct wiphy *wiphy,
                            struct net_device *dev,
                            u16 reason_code)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);

    if (mutex_lock_interruptible(&vif->lock))
        return -ERESTARTSYS;

    if (vif->sme_state == SME_DISCONNECTED) {
        mutex_unlock(&vif->lock);
        return -EINVAL;
    }

    if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        mutex_unlock(&vif->lock);
        return -EPERM;
    }

    vif->disconnect_reason_code = reason_code;

    mutex_unlock(&vif->lock);

    if (!schedule_work(&vif->ws_disconnect))
        return -EBUSY;

    return 0;
}

/* Callback called by the kernel when the user requests information about
 * a specific station. The information includes the number and bytes of
 * transmitted and received packets, signal strength, and timing information
 * such as inactive time and elapsed time since the last connection to an AP.
 * This callback is invoked when the rtnl lock has been acquired.
 */
static int vwifi_get_station(struct wiphy *wiphy,
                             struct net_device *dev,
                             const u8 *mac,
                             struct station_info *sinfo)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(dev);

    bool found_sta = false;
    switch (dev->ieee80211_ptr->iftype) {
    case NL80211_IFTYPE_AP:;
        struct vwifi_vif *sta_vif = NULL;
        list_for_each_entry (sta_vif, &vif->bss_list, bss_list) {
            if (!memcmp(mac, sta_vif->ndev->dev_addr, ETH_ALEN)) {
                found_sta = true;
                break;
            }
        }
        if (!memcmp(mac, sta_vif->ndev->dev_addr, ETH_ALEN))
            found_sta = true;
        break;
    case NL80211_IFTYPE_STATION:
        if (!memcmp(mac, vif->bssid, ETH_ALEN))
            found_sta = true;
        break;
    default:
        pr_info("vwifi: invalid interface type %u\n",
                dev->ieee80211_ptr->iftype);
        return -EINVAL;
    }

    if (!found_sta)
        return -ENONET;

    sinfo->filled = BIT_ULL(NL80211_STA_INFO_TX_PACKETS) |
                    BIT_ULL(NL80211_STA_INFO_RX_PACKETS) |
                    BIT_ULL(NL80211_STA_INFO_TX_FAILED) |
                    BIT_ULL(NL80211_STA_INFO_TX_BYTES) |
                    BIT_ULL(NL80211_STA_INFO_RX_BYTES) |
                    BIT_ULL(NL80211_STA_INFO_SIGNAL) |
                    BIT_ULL(NL80211_STA_INFO_INACTIVE_TIME);

    if (vif->sme_state == SME_CONNECTED) {
        sinfo->filled |= BIT_ULL(NL80211_STA_INFO_CONNECTED_TIME);
        sinfo->connected_time =
            jiffies_to_msecs(jiffies - vif->conn_time) / 1000;

        if (mutex_lock_interruptible(&vif->ap->lock))
            return -ENONET;

        sinfo->bss_param.beacon_interval =
            cpu_to_le16(vif->ap->beacon_int / 1024);
        sinfo->bss_param.dtim_period = 1;

        mutex_unlock(&vif->ap->lock);
        sinfo->bss_param.flags |= BSS_PARAM_FLAGS_SHORT_PREAMBLE;
    }

    sinfo->tx_packets = vif->stats.tx_packets;
    sinfo->rx_packets = vif->stats.rx_packets;
    sinfo->tx_failed = vif->stats.tx_dropped;
    sinfo->tx_bytes = vif->stats.tx_bytes;
    sinfo->rx_bytes = vif->stats.rx_bytes;
    /* For CFG80211_SIGNAL_TYPE_MBM, value is expressed in dBm */
    sinfo->signal = rand_int_smooth(-100, -30, jiffies);
    sinfo->inactive_time = jiffies_to_msecs(jiffies - vif->active_time);
    /* TODO: Emulate rate and mcs */

    return 0;
}

/* dump station callback -- resume dump at index @idx */
static int vwifi_dump_station(struct wiphy *wiphy,
                              struct net_device *dev,
                              int idx,
                              u8 *mac,
                              struct station_info *sinfo)
{
    struct vwifi_vif *ap_vif = ndev_get_vwifi_vif(dev);

    pr_info("Dump station at the idx %d\n", idx);

    int ret = -ENONET;
    struct vwifi_vif *sta_vif = NULL;
    int i = 0;

    list_for_each_entry (sta_vif, &ap_vif->bss_list, bss_list) {
        if (i < idx) {
            ++i;
            continue;
        }
        break;
    }

    if (sta_vif == ap_vif)
        return ret;

    ret = 0;

    memcpy(mac, sta_vif->ndev->dev_addr, ETH_ALEN);
    return vwifi_get_station(wiphy, dev, mac, sinfo);
}

static void vwifi_virtio_scan_complete(struct timer_list *t);

/* Create a virtual interface that has its own wiphy, not shared with other
 * interfaces. The interface mode is set to STA mode. To change the interface
 * type, use the change_virtual_intf() function.
 */
static struct wireless_dev *vwifi_interface_add(struct wiphy *wiphy)
{
    struct net_device *ndev = NULL;
    struct vwifi_vif *vif = NULL;

    /* allocate network device context. */
    ndev = alloc_netdev(sizeof(struct vwifi_vif), NDEV_NAME, NET_NAME_ENUM,
                        ether_setup);

    if (!ndev)
        goto error_alloc_ndev;

    /* fill private data of network context. */
    vif = ndev_get_vwifi_vif(ndev);
    vif->ndev = ndev;

    /* fill wireless_dev context.
     * wireless_dev with net_device can be represented as inherited class of
     * single net_device.
     */
    vif->wdev.wiphy = wiphy;
    vif->wdev.netdev = ndev;
    vif->wdev.iftype = NL80211_IFTYPE_STATION;
    vif->ndev->ieee80211_ptr = &vif->wdev;

    /* set network device hooks. should implement ndo_start_xmit() at least */
    vif->ndev->netdev_ops = &vwifi_ndev_ops;

    /* Add here proper net_device initialization */
    vif->ndev->features |= NETIF_F_HW_CSUM;

    /* The first byte is '\0' to avoid being a multicast
     * address (the first byte of multicast addrs is odd).
     */
    char intf_name[ETH_ALEN] = {0};
    snprintf(intf_name + 1, ETH_ALEN - 1, "%s%d", NAME_PREFIX,
             atomic_read(&vwifi_wiphy_counter));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
    eth_hw_addr_set(vif->ndev, intf_name);
#else
    memcpy(vif->ndev->dev_addr, intf_name, ETH_ALEN);
#endif

    /* register network device. If everything is ok, there should be new
     * network device: $ ip a
     * owl0: <BROADCAST,MULTICAST> mtu 1500 qdisc
     *       noop state DOWN group default link/ether 00:00:00:00:00:00
     *       brd ff:ff:ff:ff:ff:ff
     */
    if (register_netdev(vif->ndev))
        goto error_ndev_register;

    /* Initialize connection information */
    memset(vif->bssid, 0, ETH_ALEN);
    memset(vif->ssid, 0, IEEE80211_MAX_SSID_LEN);
    memset(vif->req_ssid, 0, IEEE80211_MAX_SSID_LEN);
    vif->scan_request = NULL;
    vif->sme_state = SME_DISCONNECTED;
    vif->conn_time = 0;
    vif->active_time = 0;
    vif->disconnect_reason_code = 0;
    vif->ap = NULL;
    vif->bss_sta_table_entry_num = 0;

    mutex_init(&vif->lock);
    mutex_init(&vif->bss_sta_table_lock);

    /* Initialize timer of scan_timeout */
    timer_setup(&vif->scan_timeout, vwifi_scan_timeout, 0);
    timer_setup(&vif->scan_complete, vwifi_virtio_scan_complete, 0);

    INIT_WORK(&vif->ws_connect, vwifi_connect_routine);
    INIT_WORK(&vif->ws_disconnect, vwifi_disconnect_routine);
    INIT_WORK(&vif->ws_scan, vwifi_scan_routine);
    INIT_WORK(&vif->ws_scan_timeout, vwifi_scan_timeout_work);

    /* Initialize rx_queue */
    INIT_LIST_HEAD(&vif->rx_queue);

    hash_init(vif->bss_sta_table);

    /* Add vif into global vif_list */
    spin_lock_bh(&vif_list_lock);
    list_add_tail(&vif->list, &vwifi->vif_list);
    spin_unlock_bh(&vif_list_lock);

    return &vif->wdev;

error_ndev_register:
    free_netdev(vif->ndev);
error_alloc_ndev:
    wiphy_unregister(wiphy);
    wiphy_free(wiphy);
    return NULL;
}

/* Called by kernel when user decided to change the interface type. */
static int vwifi_change_iface(struct wiphy *wiphy,
                              struct net_device *ndev,
                              enum nl80211_iftype type,
                              struct vif_params *params)
{
    switch (type) {
    case NL80211_IFTYPE_STATION:
    case NL80211_IFTYPE_AP:
        ndev->ieee80211_ptr->iftype = type;
        break;
    default:
        pr_info("vwifi: invalid interface type %u\n", type);
        return -EINVAL;
    }

    return 0;
}

/* Called by the kernel when the user wants to create an Access Point.
 * Currently, it adds an SSID to the SSID table to emulate the AP signal and
 * records the SSID in the vwifi_context.
 */
static int vwifi_start_ap(struct wiphy *wiphy,
                          struct net_device *ndev,
                          struct cfg80211_ap_settings *settings)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(ndev);
    struct bss_sta_entry *sta_ent;
    int ie_offset = DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
    int head_ie_len, tail_ie_len;
    unsigned long flags;
    u32 key;

    pr_info("vwifi: %s start acting in AP mode.\n", ndev->name);
    pr_info("ctrlchn=%d, center=%d, bw=%d, beacon_interval=%d, dtim_period=%d,",
            settings->chandef.chan->hw_value, settings->chandef.center_freq1,
            settings->chandef.width, settings->beacon_interval,
            settings->dtim_period);
    pr_info("ssid=%s(%zu), auth_type=%d, inactivity_timeout=%d", settings->ssid,
            settings->ssid_len, settings->auth_type,
            settings->inactivity_timeout);

    if (settings->ssid == NULL)
        return -EINVAL;

    /* Setting up AP SSID and BSSID */
    vif->ssid_len = settings->ssid_len;
    memcpy(vif->ssid, settings->ssid, settings->ssid_len);
    memcpy(vif->bssid, vif->ndev->dev_addr, ETH_ALEN);

    /* AP is the head of vif->bss_list */
    INIT_LIST_HEAD(&vif->bss_list);

    /* Add AP to global ap_list */
    list_add_tail(&vif->ap_list, &vwifi->ap_list);

    vif->ap_enabled = true;

    vif->privacy = settings->privacy;

    /* cfg80211 and some upper user-space programs treat IEs as two-part:
     * 1. head: 802.11 beacon frame header + beacon IEs before TIM IE
     * 2. tail: beacon IEs after TIM IE
     * We combine them and store them in vif->beacon_ie.
     */
    head_ie_len = settings->beacon.head_len - ie_offset;
    tail_ie_len = settings->beacon.tail_len;

    if (likely(head_ie_len + tail_ie_len <= IE_MAX_LEN)) {
        vif->beacon_ie_len = head_ie_len + tail_ie_len;
        memset(vif->beacon_ie, 0, IE_MAX_LEN);
        memcpy(vif->beacon_ie, &settings->beacon.head[ie_offset], head_ie_len);
        memcpy(vif->beacon_ie + head_ie_len, settings->beacon.tail,
               tail_ie_len);

        pr_info(
            "%s: privacy = %x, head_ie_len (before TIM IE) = %d, tail_ie_len = "
            "%d",
            __func__, settings->privacy, head_ie_len, tail_ie_len);
    } else {
        pr_info("%s: IE exceed %d bytes!\n", __func__, IE_MAX_LEN);
        return 1;
    }

    if (settings->chandef.chan) {
        pr_info("vwifi: %s center freq: %d\n", ndev->name,
                settings->chandef.chan->center_freq);
        vif->channel = settings->chandef.chan;
    }

    if (settings->chandef.width)
        vif->bw = settings->chandef.width;

    /* Default beacon interval is 100 time units */
    u64 beacon_int =
        settings->beacon_interval ? settings->beacon_interval : 100;
    /* beacon interval in us */
    vif->beacon_int = beacon_int * 1024;

    /* Initialize hrtimer of beacon */
    pr_info("vwifi: init beacon_timer.\n");
    hrtimer_init(&vif->beacon_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_SOFT);
    vif->beacon_timer.function = vwifi_beacon;

    if (!hrtimer_is_queued(&vif->beacon_timer)) {
        u64 tsf, until_tbtt;
        tsf = ktime_to_us(ktime_get_real());
        u32 bcn_int = vif->beacon_int;
        until_tbtt = bcn_int - do_div(tsf, bcn_int);

        hrtimer_start(&vif->beacon_timer,
                      ns_to_ktime(until_tbtt * NSEC_PER_USEC),
                      HRTIMER_MODE_REL_SOFT);
    }

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    if (vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

        sta_ent = kmalloc(sizeof(struct bss_sta_entry), GFP_ATOMIC);
        if (!sta_ent) {
            spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
            return 1;
        }

        memcpy(sta_ent->mac, vif->ndev->dev_addr, ETH_ALEN);
        key = vwifi_mac_to_32(sta_ent->mac);
        hash_add(vif->bss_sta_table, &sta_ent->node, key);
        vif->bss_sta_table_entry_num++;

        return 0;
    }
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    return 0;
}

static void vwifi_virtio_disconnect_tx(struct vwifi_vif *vif);

/* Called by the kernel when there is a need to "stop" from AP mode. It uses
 * the SSID to remove the AP node from the SSID table.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 2)
static int vwifi_stop_ap(struct wiphy *wiphy,
                         struct net_device *ndev,
                         unsigned int link_id)
#else
static int vwifi_stop_ap(struct wiphy *wiphy, struct net_device *ndev)
#endif
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(ndev);
    struct vwifi_vif *pos = NULL, *safe = NULL;
    struct bss_sta_entry *sta_ent;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;

    pr_info("vwifi: %s stop acting in AP mode.\n", ndev->name);

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    if (vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        vwifi_virtio_disconnect_tx(vif);

        hash_for_each_safe (vif->bss_sta_table, bkt, tmp, sta_ent, node)
            kfree(sta_ent);
        vif->bss_sta_table_entry_num = 0;

        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        return 0;
    }

    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    if (vwifi->state == VWIFI_SHUTDOWN) {
        hrtimer_cancel(&vif->beacon_timer);

        /* Destroy bss_list first */
        list_for_each_entry_safe (pos, safe, &vif->bss_list, bss_list)
            list_del(&pos->bss_list);

        /* Remove ap from global ap_list */
        if (mutex_lock_interruptible(&vwifi->lock))
            return -ERESTARTSYS;

        list_del(&vif->ap_list);

        mutex_unlock(&vwifi->lock);
    }

    vif->ap_enabled = false;

    return 0;
}

static int vwifi_change_beacon(struct wiphy *wiphy,
                               struct net_device *ndev,
                               struct cfg80211_beacon_data *info)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(ndev);
    int ie_offset = DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN;
    int head_ie_len, tail_ie_len;

    /* cfg80211 and some user-space programs treat IEs as two-part:
     * 1. head: 802.11 beacon frame header + beacon IEs before TIM IE
     * 2. tail: beacon IEs after TIM IE
     * We combine them and store them in vif->beacon_ie.
     */
    head_ie_len = info->head_len - ie_offset;
    tail_ie_len = info->tail_len;

    if (likely(head_ie_len + tail_ie_len <= IE_MAX_LEN)) {
        vif->beacon_ie_len = head_ie_len + tail_ie_len;
        memset(vif->beacon_ie, 0, IE_MAX_LEN);
        memcpy(vif->beacon_ie, &info->head[ie_offset], head_ie_len);
        memcpy(vif->beacon_ie + head_ie_len, info->tail, tail_ie_len);

        pr_info(
            "%s: head_ie_len (before TIM IE) = %d, tail_ie_len = "
            "%d",
            __func__, head_ie_len, tail_ie_len);
    } else {
        pr_info("%s: IE exceed %d bytes!\n", __func__, IE_MAX_LEN);
        return 1;
    }

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int vwifi_add_key(struct wiphy *wiphy,
                         struct net_device *ndev,
                         int link_id,
                         u8 key_idx,
                         bool pairwise,
                         const u8 *mac_addr,
                         struct key_params *params)
#else
static int vwifi_add_key(struct wiphy *wiphy,
                         struct net_device *ndev,
                         u8 key_idx,
                         bool pairwise,
                         const u8 *mac_addr,
                         struct key_params *params)
#endif
{
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int vwifi_del_key(struct wiphy *wiphy,
                         struct net_device *ndev,
                         int link_id,
                         u8 key_idx,
                         bool pairwise,
                         const u8 *mac_addr)
#else
static int vwifi_del_key(struct wiphy *wiphy,
                         struct net_device *ndev,
                         u8 key_idx,
                         bool pairwise,
                         const u8 *mac_addr)
#endif
{
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int vwifi_set_default_key(struct wiphy *wiphy,
                                 struct net_device *ndev,
                                 int link_id,
                                 u8 key_idx,
                                 bool unicast,
                                 bool multicast)
#else
static int vwifi_set_default_key(struct wiphy *wiphy,
                                 struct net_device *ndev,
                                 u8 key_idx,
                                 bool unicast,
                                 bool multicast)
#endif
{
    return 0;
}

static void vwifi_virtio_sta_entry_request(struct vwifi_vif *vif,
                                           const u8 *bssid);
static void vwifi_virtio_sta_entry_response(struct vwifi_vif *vif,
                                            enum VWIFI_STA_ENTRY_CMD cmd,
                                            const u8 *sta);

static int vwifi_change_station(struct wiphy *wiphy,
                                struct net_device *ndev,
                                const u8 *mac,
                                struct station_parameters *params)
{
    struct vwifi_vif *vif = ndev_get_vwifi_vif(ndev);
    struct bss_sta_entry *sta_entry;
    unsigned long flags;
    u32 key;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    if (!vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        return -EINVAL;
    }
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    /* For now, we only care about the authorized (802.1X) event. */
    if (!(params->sta_flags_set & BIT(NL80211_STA_FLAG_AUTHORIZED)))
        return 0;

    if (is_zero_ether_addr(mac))
        return 0;

    /* For AP, we broadcast an unsolicited `VWIFI_STA_ENTRY_RESPONSE`
     * which contains the newly connected STA's MAC, so that other
     * STAs know the existent of the STA.
     */
    if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        sta_entry = kmalloc(sizeof(struct bss_sta_entry), GFP_KERNEL);
        if (!sta_entry)
            return -ENOMEM;

        memcpy(sta_entry->mac, mac, ETH_ALEN);

        mutex_lock(&vif->bss_sta_table_lock);

        /* We use a very naive method here to map 6-bytes MAC
         * into a 8-bytes integer so that we could pass it
         * into hash_add() as a key. Please optimize it.
         */
        key = vwifi_mac_to_32(mac);
        hash_add(vif->bss_sta_table, &sta_entry->node, key);
        vif->bss_sta_table_entry_num++;

        mutex_unlock(&vif->bss_sta_table_lock);

        vwifi_virtio_sta_entry_response(vif, VWIFI_STA_ENTRY_ADD, mac);
    }
    /* For STA, we send a `VWIFI_STA_ENTRY_REQUEST` for the newly
     * conncted AP to ask about the STAs in the BSS.
     */
    else if (vif->wdev.iftype == NL80211_IFTYPE_STATION) {
        if (mutex_lock_interruptible(&vif->lock))
            return -ERESTARTSYS;

        memcpy(vif->ssid, vif->req_ssid, vif->ssid_len);
        memcpy(vif->bssid, mac, ETH_ALEN);
        vif->sme_state = SME_CONNECTED;
        vif->conn_time = jiffies;

        mutex_unlock(&vif->lock);

        vwifi_virtio_sta_entry_request(vif, mac);
    }

    return 0;
}

/* Unregister and free a virtual interface identified by @vif->ndev. */
static int vwifi_delete_interface(struct vwifi_vif *vif)
{
    struct vwifi_packet *pkt = NULL, *safe = NULL;
    struct wiphy *wiphy = vif->wdev.wiphy;
    struct bss_sta_entry *sta_ent;
    struct hlist_node *tmp;
    int bkt;

    /* Stop TX queue, and delete the pending packets */
    netif_stop_queue(vif->ndev);
    list_for_each_entry_safe (pkt, safe, &vif->rx_queue, list) {
        list_del(&pkt->list);
        kfree(pkt);
    }

    hash_for_each_safe (vif->bss_sta_table, bkt, tmp, sta_ent, node)
        kfree(sta_ent);

    if (vif->wdev.iftype == NL80211_IFTYPE_STATION) {
        if (mutex_lock_interruptible(&vif->lock))
            return -ERESTARTSYS;

        cancel_work_sync(&vif->ws_scan);
        cancel_work_sync(&vif->ws_scan_timeout);
        del_timer_sync(&vif->scan_complete);

        /* If there's a pending scan, call cfg80211_scan_done to finish it. */
        if (vif->scan_request) {
            struct cfg80211_scan_info info = {.aborted = true};

            cfg80211_scan_done(vif->scan_request, &info);
            vif->scan_request = NULL;
        }

        /* Make sure that no work is queued */
        del_timer_sync(&vif->scan_timeout);
        cancel_work_sync(&vif->ws_connect);
        cancel_work_sync(&vif->ws_disconnect);

        mutex_unlock(&vif->lock);
    }

    /* Deallocate net_device */
    unregister_netdev(vif->ndev);
    free_netdev(vif->ndev);

    /* Deallocate wiphy device */
    wiphy_unregister(wiphy);
    wiphy_free(wiphy);

    return 0;
}

/* Structure of functions for FullMAC 80211 drivers. Functions implemented
 * along with fields/flags in the wiphy structure represent driver features.
 * This module can only perform "scan" and "connect". Some functions cannot
 * be implemented alone. For example, with "connect" there should be a
 * corresponding "disconnect" function.
 */
static struct cfg80211_ops vwifi_cfg_ops = {
    .change_virtual_intf = vwifi_change_iface,
    .scan = vwifi_scan,
    .connect = vwifi_connect,
    .disconnect = vwifi_disconnect,
    .get_station = vwifi_get_station,
    .dump_station = vwifi_dump_station,
    .start_ap = vwifi_start_ap,
    .stop_ap = vwifi_stop_ap,
    .change_beacon = vwifi_change_beacon,
    .add_key = vwifi_add_key,
    .del_key = vwifi_del_key,
    .set_default_key = vwifi_set_default_key,
    .change_station = vwifi_change_station,
};

/* Macro for defining 2GHZ channel array */
#define CHAN_2GHZ(channel, freq)                          \
    {                                                     \
        .band = NL80211_BAND_2GHZ, .hw_value = (channel), \
        .center_freq = (freq),                            \
    }

/* Macro for defining 5GHZ channel array */
#define CHAN_5GHZ(channel)                                \
    {                                                     \
        .band = NL80211_BAND_5GHZ, .hw_value = (channel), \
        .center_freq = 5000 + (5 * (channel)),            \
    }

/* Macro for defining rate table */
#define RATE_ENT(_rate, _hw_value)                   \
    {                                                \
        .bitrate = (_rate), .hw_value = (_hw_value), \
    }

/* Array of "supported" channels in 2GHz band. It is required for wiphy. */
static const struct ieee80211_channel vwifi_supported_channels_2ghz[] = {
    CHAN_2GHZ(1, 2412),  CHAN_2GHZ(2, 2417),  CHAN_2GHZ(3, 2422),
    CHAN_2GHZ(4, 2427),  CHAN_2GHZ(5, 2432),  CHAN_2GHZ(6, 2437),
    CHAN_2GHZ(7, 2442),  CHAN_2GHZ(8, 2447),  CHAN_2GHZ(9, 2452),
    CHAN_2GHZ(10, 2457), CHAN_2GHZ(11, 2462), CHAN_2GHZ(12, 2467),
    CHAN_2GHZ(13, 2472), CHAN_2GHZ(14, 2484),
};

/* Array of "supported" channels in 5GHz band. It is required for wiphy. */
static const struct ieee80211_channel vwifi_supported_channels_5ghz[] = {
    CHAN_5GHZ(34),  CHAN_5GHZ(36),  CHAN_5GHZ(38),  CHAN_5GHZ(40),
    CHAN_5GHZ(42),  CHAN_5GHZ(44),  CHAN_5GHZ(46),  CHAN_5GHZ(48),
    CHAN_5GHZ(52),  CHAN_5GHZ(56),  CHAN_5GHZ(60),  CHAN_5GHZ(64),
    CHAN_5GHZ(100), CHAN_5GHZ(104), CHAN_5GHZ(108), CHAN_5GHZ(112),
    CHAN_5GHZ(116), CHAN_5GHZ(120), CHAN_5GHZ(124), CHAN_5GHZ(128),
    CHAN_5GHZ(132), CHAN_5GHZ(136), CHAN_5GHZ(140), CHAN_5GHZ(144),
    CHAN_5GHZ(149), CHAN_5GHZ(153), CHAN_5GHZ(157), CHAN_5GHZ(161),
    CHAN_5GHZ(165),
};

/* Array of supported rates, required to support those next rates
 * for 2GHz and 5GHz band.
 */
static const struct ieee80211_rate vwifi_supported_rates[] = {
    RATE_ENT(10, 0x1),    RATE_ENT(20, 0x2),    RATE_ENT(55, 0x4),
    RATE_ENT(110, 0x8),   RATE_ENT(60, 0x10),   RATE_ENT(90, 0x20),
    RATE_ENT(120, 0x40),  RATE_ENT(180, 0x80),  RATE_ENT(240, 0x100),
    RATE_ENT(360, 0x200), RATE_ENT(480, 0x400), RATE_ENT(540, 0x800),
};

/* Describes supported band of 2GHz. */
static struct ieee80211_supported_band nf_band_2ghz;

/* Describes supported band of 5GHz. */
static struct ieee80211_supported_band nf_band_5ghz;

/* Unregister and free virtual interfaces and wiphy. */
static void vwifi_free(void)
{
    struct vwifi_vif *vif = NULL, *safe = NULL;

    spin_lock_bh(&vif_list_lock);
    list_for_each_entry_safe (vif, safe, &vwifi->vif_list, list) {
        spin_unlock_bh(&vif_list_lock);
        vwifi_delete_interface(vif);
        spin_lock_bh(&vif_list_lock);
    }
    spin_unlock_bh(&vif_list_lock);

    kfree(vwifi->blocklist);
    kfree(vwifi);
}

/* Allocate and register wiphy.
 * Virtual interfaces should be created by nl80211, which will call
 * cfg80211_ops->add_iface(). This program creates a wiphy for every
 * virtual interface, which means a virtual interface has a physical (virtual)
 * adapter associated with it.
 */
static struct wiphy *vwifi_cfg80211_add(void)
{
    struct wiphy *wiphy = NULL;
    enum nl80211_band band;

    /* In order to customize vwifi's wiphy name, we use vwifi_wiphy_counter to
     * keep track of the number of wiphy in vwifi, and use vwifi_wiphy_idx to
     * retreive the value of vwifi_wiphy_counter.
     */
    int vwifi_wiphy_idx = atomic_inc_return(&vwifi_wiphy_counter);

    /* atomic_inc_return makes it start at 1, make it start at 0 */
    vwifi_wiphy_idx--;
    if (unlikely(vwifi_wiphy_idx < 0)) {
        atomic_dec(&vwifi_wiphy_counter);
        return NULL;
    }

    /* allocate wiphy context. It is possible just to use wiphy_new().
     * wiphy should represent physical FullMAC wireless device. We need
     * to implement add_virtual_intf() from cfg80211_ops for adding
     * interface(s) on top of a wiphy.
     * NULL means use the default phy%d naming.
     * vwifi_wiphy_name is the custom-made vw_phy%d naming we use for
     * wiphy in vwifi.
     */

    /* Reference:
     * https://elixir.bootlin.com/linux/v6.7/source/net/wireless/core.c#L447
     * The default phy%d naming for wiphy in linux kernel depends on the value
     * of a static variable wiphy_counter. The value of wiphy_counter will never
     * decrease even if we unregister the wiphy. This behavior ensures that the
     * naming and indexing for `struct wiphy` will be absolutely unique.
     * However, the kernel might have other modules or projects also utilizing
     * `struct wiphy`, which will cause some confusion of wiphy's index and
     * naming when using the default naming scheme. We implement a custom-made
     * name "vw_phy%d" for wiphy in vwifi device driver, in order to seperate
     * the naming and indexing for `struct wiphy` in vwifi.
     */
    char vwifi_wiphy_name[VWIFI_WIPHY_NAME_LEN] = {0};
    snprintf(vwifi_wiphy_name, VWIFI_WIPHY_NAME_LEN, "%s%d", VWIFI_WIPHY_PREFIX,
             vwifi_wiphy_idx);

    wiphy = wiphy_new_nm(&vwifi_cfg_ops, 0, vwifi_wiphy_name);
    if (!wiphy) {
        pr_info("couldn't allocate wiphy device\n");
        return NULL;
    }

    /* FIXME: set device object as wiphy "parent" */
    /* set_wiphy_dev(ret->wiphy, dev); */

    /* wiphy should determinate its type.
     * add other required types like  "BIT(NL80211_IFTYPE_STATION) |
     * BIT(NL80211_IFTYPE_AP)" etc.
     */
    wiphy->interface_modes =
        BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP);

    for (band = NL80211_BAND_2GHZ; band < NUM_NL80211_BANDS; band++) {
        /* FIXME: add other band capabilities if needed, such as 40 width */
        switch (band) {
        case NL80211_BAND_2GHZ:
            nf_band_2ghz.ht_cap.cap = IEEE80211_HT_CAP_SGI_20;
            nf_band_2ghz.ht_cap.ht_supported = false;
            nf_band_2ghz.channels =
                kmemdup(vwifi_supported_channels_2ghz,
                        sizeof(vwifi_supported_channels_2ghz), GFP_KERNEL);
            nf_band_2ghz.n_channels = ARRAY_SIZE(vwifi_supported_channels_2ghz);
            nf_band_2ghz.bitrates =
                kmemdup(vwifi_supported_rates, sizeof(vwifi_supported_rates),
                        GFP_KERNEL);
            nf_band_2ghz.n_bitrates = ARRAY_SIZE(vwifi_supported_rates);
            wiphy->bands[band] = &nf_band_2ghz;
            break;
        case NL80211_BAND_5GHZ:
            nf_band_5ghz.channels =
                kmemdup(vwifi_supported_channels_5ghz,
                        sizeof(vwifi_supported_channels_5ghz), GFP_KERNEL);
            nf_band_5ghz.n_channels = ARRAY_SIZE(vwifi_supported_channels_5ghz);
            nf_band_5ghz.bitrates =
                kmemdup(vwifi_supported_rates + 4,
                        (ARRAY_SIZE(vwifi_supported_rates) - 4) *
                            sizeof(struct ieee80211_rate),
                        GFP_KERNEL);
            nf_band_5ghz.n_bitrates = ARRAY_SIZE(vwifi_supported_rates) - 4;
            wiphy->bands[band] = &nf_band_5ghz;
            break;
        default:
            continue;
        }
    }

    /* scan - if the device supports "scan", we need to define max_scan_ssids
     * at least.
     */
    wiphy->max_scan_ssids = MAX_PROBED_SSIDS;
    wiphy->max_scan_ie_len = IE_MAX_LEN;

    /* Signal type
     * CFG80211_SIGNAL_TYPE_UNSPEC allows us specify signal strength from 0 to
     * 100. The reasonable value for CFG80211_SIGNAL_TYPE_MBM is -3000 to -10000
     * (mdBm).
     */
    wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

    wiphy->flags |= WIPHY_FLAG_NETNS_OK;

    wiphy->cipher_suites = vwifi_cipher_suites;
    wiphy->n_cipher_suites = ARRAY_SIZE(vwifi_cipher_suites);

    /* register wiphy, if everything ok - there should be another wireless
     * device in system. use command: $ iw list
     */
    if (wiphy_register(wiphy) < 0) {
        pr_info("couldn't register wiphy device\n");
        goto error_wiphy_register;
    }

    return wiphy;

error_wiphy_register:
    wiphy_free(wiphy);
    return NULL;
}

static void vwifi_virtio_scan_complete(struct timer_list *t)
{
    struct vwifi_vif *vif = container_of(t, struct vwifi_vif, scan_complete);
    struct cfg80211_scan_info info = {
        .aborted = false,
    };

    if (mutex_lock_interruptible(&vif->lock))
        return;

    cfg80211_scan_done(vif->scan_request, &info);

    vif->scan_request = NULL;

    mutex_unlock(&vif->lock);
}

static void vwifi_virtio_scan_request(struct vwifi_vif *vif)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct vwifi_virtio_header *vvh;
    struct vwifi_virtio_scan_req *scan_req;
    int len = ETH_HLEN + VWIFI_VIRTIO_HEADER_TYPE_BYTE +
              sizeof(struct vwifi_virtio_scan_req);
    bool wildcard_ssid = false;

    if (!vif->scan_request)
        return;

    skb = dev_alloc_skb(len);
    if (!skb)
        return;

    skb_put(skb, len);

    eth = (struct ethhdr *) skb->data;
    eth_broadcast_addr(eth->h_dest);
    memcpy(eth->h_source, vif->ndev->dev_addr, ETH_ALEN);

    /* We treat our management frame as 802.3 type, so we put length here */
    eth->h_proto = htons(len);

    vvh = (struct vwifi_virtio_header *) (eth + 1);
    vvh->type = cpu_to_le16(VWIFI_SCAN_REQUEST);

    scan_req = (struct vwifi_virtio_scan_req *) ((u8 *) vvh +
                                                 VWIFI_VIRTIO_HEADER_TYPE_BYTE);

    if (!vif->scan_request->n_ssids || !vif->scan_request->ssids[0].ssid_len)
        wildcard_ssid = true;

    if (wildcard_ssid)
        scan_req->ssid_len = 0;
    else {
        scan_req->ssid_len = cpu_to_le32(vif->scan_request->ssids[0].ssid_len);
        memcpy(scan_req->ssid, vif->scan_request->ssids[0].ssid,
               vif->scan_request->ssids[0].ssid_len);
    }

    vwifi_virtio_tx(vif, skb);

    mod_timer(&vif->scan_timeout, jiffies + msecs_to_jiffies(2000));
}

static void vwifi_virtio_connect_request(struct vwifi_vif *vif)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct vwifi_virtio_header *vvh;
    struct vwifi_virtio_conn_req *conn_req;
    int len = ETH_HLEN + VWIFI_VIRTIO_HEADER_TYPE_BYTE +
              sizeof(struct vwifi_virtio_conn_req);

    skb = dev_alloc_skb(len);
    if (!skb)
        return;

    skb_put(skb, len);

    eth = (struct ethhdr *) skb->data;
    memcpy(eth->h_dest, vif->req_bssid, ETH_ALEN);
    memcpy(eth->h_source, vif->ndev->dev_addr, ETH_ALEN);

    /* We treat our management frame as 802.3 type, so we put length here */
    eth->h_proto = htons(len);

    vvh = (struct vwifi_virtio_header *) (eth + 1);
    vvh->type = cpu_to_le16(VWIFI_CONNECT_REQUEST);

    conn_req = (struct vwifi_virtio_conn_req *) ((u8 *) vvh +
                                                 VWIFI_VIRTIO_HEADER_TYPE_BYTE);
    memcpy(conn_req->bssid, vif->req_bssid, ETH_ALEN);
    conn_req->ssid_len = cpu_to_le32(vif->ssid_len);
    memcpy(conn_req->ssid, vif->req_ssid, vif->ssid_len);

    vwifi_virtio_tx(vif, skb);
}

static void vwifi_virtio_disconnect_tx(struct vwifi_vif *vif);

static void vwifi_virtio_disconnect(struct vwifi_vif *vif)
{
    vwifi_virtio_disconnect_tx(vif);

    cfg80211_disconnected(vif->ndev, vif->disconnect_reason_code, NULL, 0, true,
                          GFP_KERNEL);

    if (mutex_lock_interruptible(&vif->lock))
        return;

    vif->disconnect_reason_code = 0;
    vif->sme_state = SME_DISCONNECTED;
    memset(vif->bssid, 0, ETH_ALEN);

    mutex_unlock(&vif->lock);
}

static void vwifi_virtio_disconnect_tx(struct vwifi_vif *vif)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct vwifi_virtio_header *vvh;
    struct vwifi_virtio_disconn *disconn;
    int len = ETH_HLEN + VWIFI_VIRTIO_HEADER_TYPE_BYTE +
              sizeof(struct vwifi_virtio_disconn);

    skb = dev_alloc_skb(len);
    if (!skb)
        return;

    skb_put(skb, len);

    eth = (struct ethhdr *) skb->data;
    memcpy(eth->h_source, vif->ndev->dev_addr, ETH_ALEN);

    if (vif->wdev.iftype == NL80211_IFTYPE_STATION)
        memcpy(eth->h_dest, vif->bssid, ETH_ALEN);
    /* right now AP only sent disconnect frame when cfg80211->stop_ap() */
    else if (vif->wdev.iftype == NL80211_IFTYPE_AP)
        eth_broadcast_addr(eth->h_dest);
    else
        return;

    /* We treat our management frame as 802.3 type, so we put length here */
    eth->h_proto = htons(len);

    vvh = (struct vwifi_virtio_header *) (eth + 1);
    vvh->type = cpu_to_le16(VWIFI_DISCONNECT);

    disconn = (struct vwifi_virtio_disconn *) ((u8 *) vvh +
                                               VWIFI_VIRTIO_HEADER_TYPE_BYTE);
    memcpy(disconn->bssid, vif->bssid, ETH_ALEN);
    disconn->reason_code = cpu_to_le16(vif->disconnect_reason_code);

    vwifi_virtio_tx(vif, skb);
}

static void vwifi_virtio_sta_entry_request(struct vwifi_vif *vif,
                                           const u8 *bssid)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct vwifi_virtio_header *vvh;
    int len = ETH_HLEN + VWIFI_VIRTIO_HEADER_TYPE_BYTE;

    if (vif->wdev.iftype != NL80211_IFTYPE_STATION)
        return;

    skb = dev_alloc_skb(len);
    if (!skb)
        return;

    skb_put(skb, len);

    eth = (struct ethhdr *) skb->data;
    memcpy(eth->h_dest, bssid, ETH_ALEN);
    memcpy(eth->h_source, vif->ndev->dev_addr, ETH_ALEN);

    /* We treat our management frame as 802.3 type, so we put length here */
    eth->h_proto = htons(len);

    vvh = (struct vwifi_virtio_header *) (eth + 1);
    vvh->type = cpu_to_le16(VWIFI_STA_ENTRY_REQUEST);

    vwifi_virtio_tx(vif, skb);
}


static void vwifi_virtio_sta_entry_response(struct vwifi_vif *vif,
                                            enum VWIFI_STA_ENTRY_CMD cmd,
                                            const u8 *sta)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct vwifi_virtio_header *vvh;
    struct vwifi_virtio_sta_entry_resp *sta_ent_resp;
    struct bss_sta_entry *sta_ent;
    int len = ETH_HLEN + VWIFI_VIRTIO_HEADER_TYPE_BYTE +
              sizeof(struct vwifi_virtio_sta_entry_resp);
    u32 bkt;
    u8 *map_p;

    if (vif->wdev.iftype != NL80211_IFTYPE_AP)
        return;

    if (cmd == VWIFI_STA_ENTRY_ADD || cmd == VWIFI_STA_ENTRY_DEL)
        len += ETH_ALEN;
    else if (cmd == VWIFI_STA_ENTRY_ADD_ALL)
        len += vif->bss_sta_table_entry_num * ETH_ALEN;
    else
        return;

    /* Fix me. We should fragment the frame if the size of the
     * VWIFI_STA_ENTRY_RESPONSE frame exceeds the maximum Ethernet
     * frame length.
     */
    if (len > ETH_FRAME_LEN) {
        pr_info("%s: length %d exceeds ETH_FRAME_LEN, ignore.\n", __func__,
                len);
        return;
    }

    skb = dev_alloc_skb(len);
    if (!skb)
        return;

    skb_put(skb, len);

    eth = (struct ethhdr *) skb->data;
    memcpy(eth->h_source, vif->ndev->dev_addr, ETH_ALEN);

    if (cmd == VWIFI_STA_ENTRY_ADD || cmd == VWIFI_STA_ENTRY_DEL)
        eth_broadcast_addr(eth->h_dest);
    else if (cmd == VWIFI_STA_ENTRY_ADD_ALL)
        memcpy(eth->h_dest, sta, ETH_ALEN);
    else
        goto out_free_skb;

    /* We treat our management frame as 802.3 type, so we put length here */
    eth->h_proto = htons(len);

    vvh = (struct vwifi_virtio_header *) (eth + 1);
    vvh->type = cpu_to_le16(VWIFI_STA_ENTRY_RESPONSE);

    sta_ent_resp =
        (struct vwifi_virtio_sta_entry_resp *) ((u8 *) vvh +
                                                VWIFI_VIRTIO_HEADER_TYPE_BYTE);
    memcpy(sta_ent_resp->bssid, vif->ndev->dev_addr, ETH_ALEN);
    sta_ent_resp->cmd = cpu_to_le16(cmd);

    if (cmd == VWIFI_STA_ENTRY_ADD || cmd == VWIFI_STA_ENTRY_DEL) {
        sta_ent_resp->count = cpu_to_le32(1);
        memcpy(sta_ent_resp->macs, sta, ETH_ALEN);
    } else if (cmd == VWIFI_STA_ENTRY_ADD_ALL) {
        sta_ent_resp->count = cpu_to_le32(vif->bss_sta_table_entry_num);

        mutex_lock(&vif->bss_sta_table_lock);

        map_p = sta_ent_resp->macs;
        hash_for_each (vif->bss_sta_table, bkt, sta_ent, node) {
            memcpy(map_p, sta_ent->mac, ETH_ALEN);
            map_p += ETH_ALEN;
        }

        mutex_unlock(&vif->bss_sta_table_lock);
    } else
        goto out_free_skb;

    vwifi_virtio_tx(vif, skb);

    return;

out_free_skb:
    dev_kfree_skb(skb);
}

static void vwifi_virtio_mgmt_rx_sta_entry_response(
    struct vwifi_vif *vif,
    const u8 *src,
    struct vwifi_virtio_sta_entry_resp *sta_ent_resp)
{
    struct bss_sta_entry *sta_ent;
    int i;
    u32 key;
    u16 cmd = le16_to_cpu(sta_ent_resp->cmd);
    u8 *mac_p;

    if (vif->wdev.iftype != NL80211_IFTYPE_STATION)
        return;

    if (!ether_addr_equal(sta_ent_resp->bssid, vif->bssid))
        return;

    mutex_lock(&vif->bss_sta_table_lock);

    mac_p = sta_ent_resp->macs;
    for (i = 0; i < le32_to_cpu(sta_ent_resp->count); i++) {
        if (ether_addr_equal(mac_p, vif->ndev->dev_addr)) {
            mac_p += ETH_ALEN;
            continue;
        }

        if (cmd == VWIFI_STA_ENTRY_ADD || cmd == VWIFI_STA_ENTRY_ADD_ALL) {
            sta_ent = kmalloc(sizeof(struct bss_sta_entry), GFP_KERNEL);
            if (!sta_ent)
                goto out_unlock;

            memcpy(sta_ent->mac, mac_p, ETH_ALEN);
            key = vwifi_mac_to_32(sta_ent->mac);
            hash_add(vif->bss_sta_table, &sta_ent->node, key);
            vif->bss_sta_table_entry_num++;
        } else if (cmd == VWIFI_STA_ENTRY_DEL) {
            key = vwifi_mac_to_32(mac_p);
            hash_for_each_possible (vif->bss_sta_table, sta_ent, node, key) {
                if (ether_addr_equal(sta_ent->mac, mac_p)) {
                    hlist_del_init(&sta_ent->node);
                    kfree(sta_ent);
                    vif->bss_sta_table_entry_num--;
                    break;
                }
            }
        } else
            goto out_unlock;

        mac_p += ETH_ALEN;

        if (unlikely((unsigned long) mac_p -
                         ((unsigned long) sta_ent_resp -
                          VWIFI_VIRTIO_HEADER_TYPE_BYTE - ETH_HLEN) >
                     ETH_FRAME_LEN))
            goto out_unlock;
    }
out_unlock:
    mutex_unlock(&vif->bss_sta_table_lock);
}

static void vwifi_virtio_mgmt_rx_sta_entry_request(struct vwifi_vif *vif,
                                                   const u8 *src)
{
    if (vif->wdev.iftype != NL80211_IFTYPE_AP)
        return;

    vwifi_virtio_sta_entry_response(vif, VWIFI_STA_ENTRY_ADD_ALL, src);
}

static void vwifi_virtio_mgmt_rx_disconnect(
    struct vwifi_vif *vif,
    const u8 *src,
    struct vwifi_virtio_disconn *disconn)
{
    struct bss_sta_entry *tmp;
    u32 key;

    if (vif->wdev.iftype == NL80211_IFTYPE_STATION) {
        cfg80211_disconnected(vif->ndev, vif->disconnect_reason_code, NULL, 0,
                              true, GFP_KERNEL);

        if (mutex_lock_interruptible(&vif->lock))
            return;

        vif->disconnect_reason_code = 0;
        vif->sme_state = SME_DISCONNECTED;
        memset(vif->bssid, 0, ETH_ALEN);

        mutex_unlock(&vif->lock);
    } else if (vif->wdev.iftype == NL80211_IFTYPE_AP) {
        cfg80211_del_sta(vif->ndev, src, GFP_KERNEL);

        mutex_lock(&vif->bss_sta_table_lock);

        key = vwifi_mac_to_32(src);
        hash_for_each_possible (vif->bss_sta_table, tmp, node, key) {
            if (ether_addr_equal(tmp->mac, src)) {
                hlist_del_init(&tmp->node);
                kfree(tmp);
                break;
            }
        }

        mutex_unlock(&vif->bss_sta_table_lock);

        vwifi_virtio_sta_entry_response(vif, VWIFI_STA_ENTRY_DEL, src);
    }
}

static void vwifi_virtio_mgmt_rx_connect_response(
    struct vwifi_vif *vif,
    const u8 *src,
    struct vwifi_virtio_conn_resp *conn_resp)
{
    if (vif->wdev.iftype != NL80211_IFTYPE_STATION)
        return;

    cfg80211_connect_result(vif->ndev, vif->req_bssid, NULL, 0, NULL, 0,
                            le16_to_cpu(conn_resp->status_code), GFP_KERNEL);

    if (!(le16_to_cpu(conn_resp->capab_info) & WLAN_CAPABILITY_PRIVACY)) {
        if (mutex_lock_interruptible(&vif->lock))
            return;

        memcpy(vif->ssid, vif->req_ssid, vif->ssid_len);
        memcpy(vif->bssid, vif->req_bssid, ETH_ALEN);
        vif->sme_state = SME_CONNECTED;
        vif->conn_time = jiffies;

        mutex_unlock(&vif->lock);

        vwifi_virtio_sta_entry_request(vif, vif->bssid);
    }
    /* Otherwise we defer the AP info's update to cfg80211_ops->change_station()
     */
}

static void vwifi_virtio_mgmt_rx_connect_request(
    struct vwifi_vif *vif,
    const u8 *src,
    struct vwifi_virtio_conn_req *conn_req)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct vwifi_virtio_header *vvh;
    struct vwifi_virtio_conn_resp *conn_resp;
    struct bss_sta_entry *sta_ent;
    struct station_info *sinfo;
    int len = ETH_HLEN + VWIFI_VIRTIO_HEADER_TYPE_BYTE +
              sizeof(struct vwifi_virtio_conn_resp);
    u32 key;

    if (vif->wdev.iftype != NL80211_IFTYPE_AP)
        return;

    if (!ether_addr_equal(vif->ndev->dev_addr, conn_req->bssid) ||
        vif->ssid_len != le32_to_cpu(conn_req->ssid_len) ||
        memcmp(vif->ssid, conn_req->ssid, vif->ssid_len))
        return;

    /* Ignore the STA which has been connected */
    key = vwifi_mac_to_32(src);
    hash_for_each_possible (vif->bss_sta_table, sta_ent, node, key)
        if (ether_addr_equal(sta_ent->mac, src))
            return;

    sinfo = kmalloc(sizeof(struct station_info), GFP_KERNEL);
    if (!sinfo)
        return;

    skb = dev_alloc_skb(len);
    if (!skb)
        goto out_free_sinfo;

    skb_put(skb, len);

    eth = (struct ethhdr *) skb->data;
    memcpy(eth->h_dest, src, ETH_ALEN);
    memcpy(eth->h_source, vif->ndev->dev_addr, ETH_ALEN);

    /* We treat our management frame as 802.3 type, so we put length here */
    eth->h_proto = htons(len);

    vvh = (struct vwifi_virtio_header *) (eth + 1);
    vvh->type = cpu_to_le16(VWIFI_CONNECT_RESPONSE);

    conn_resp =
        (struct vwifi_virtio_conn_resp *) ((u8 *) vvh +
                                           VWIFI_VIRTIO_HEADER_TYPE_BYTE);
    conn_resp->status_code = cpu_to_le16(WLAN_STATUS_SUCCESS);
    conn_resp->capab_info = cpu_to_le16(WLAN_CAPABILITY_ESS);
    conn_resp->capab_info |=
        vif->privacy ? cpu_to_le16(WLAN_CAPABILITY_PRIVACY) : 0;

    vwifi_virtio_tx(vif, skb);

    if (!vif->privacy) {
        sta_ent = kmalloc(sizeof(struct bss_sta_entry), GFP_KERNEL);
        if (!sta_ent)
            goto out_free_sinfo;

        memcpy(sta_ent->mac, src, ETH_ALEN);

        mutex_lock(&vif->bss_sta_table_lock);

        hash_add(vif->bss_sta_table, &sta_ent->node, key);
        vif->bss_sta_table_entry_num++;

        mutex_unlock(&vif->bss_sta_table_lock);

        vwifi_virtio_sta_entry_response(vif, VWIFI_STA_ENTRY_ADD, src);
    }

    /* It is safe that we fake the association request IEs
     * by beacon IEs, since they both possibly have the WPA/RSN IE
     * which is what the upper user-space program (e.g. hostapd)
     * cares about.
     */
    sinfo->assoc_req_ies = vif->beacon_ie;
    sinfo->assoc_req_ies_len = vif->beacon_ie_len;

    /* nl80211 will inform the user-space program (e.g. hostapd)
     * about the newly-associated station via generic netlink
     * command NL80211_CMD_NEW_STATION for latter processing
     * (e.g. 4-way handshake).
     */
    cfg80211_new_sta(vif->ndev, src, sinfo, GFP_KERNEL);

out_free_sinfo:
    kfree(sinfo);
}

static void vwifi_virtio_mgmt_rx_scan_response(
    struct vwifi_vif *vif,
    const u8 *src,
    struct vwifi_virtio_scan_resp *scan_resp)
{
    struct cfg80211_bss *bss;

    if (vif->wdev.iftype != NL80211_IFTYPE_STATION)
        return;

    struct ieee80211_channel rx_channel = {
        .band = NL80211_BAND_2GHZ,
        .center_freq = le32_to_cpu(scan_resp->channel),
    };
    struct cfg80211_inform_bss data = {
        .chan = &rx_channel,
        .scan_width = NL80211_BSS_CHAN_WIDTH_20,
        .signal = DBM_TO_MBM(rand_int_smooth(-100, -30, jiffies)),
    };

    bss = cfg80211_inform_bss_data(
        vif->wdev.wiphy, &data, CFG80211_BSS_FTYPE_UNKNOWN, scan_resp->bssid,
        le64_to_cpu(scan_resp->timestamp), le16_to_cpu(scan_resp->capab_info),
        100, scan_resp->beacon_ies, le32_to_cpu(scan_resp->beacon_ies_len),
        GFP_KERNEL);

    cfg80211_put_bss(vif->wdev.wiphy, bss);
}

static void vwifi_virtio_mgmt_rx_scan_request(
    struct vwifi_vif *vif,
    const u8 src[ETH_ALEN],
    struct vwifi_virtio_scan_req *scan_req)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct vwifi_virtio_header *vvh;
    struct vwifi_virtio_scan_resp *scan_resp;
    int len = ETH_HLEN + VWIFI_VIRTIO_HEADER_TYPE_BYTE +
              sizeof(struct vwifi_virtio_scan_resp) + vif->beacon_ie_len;

    if (vif->wdev.iftype != NL80211_IFTYPE_AP)
        return;

    if (scan_req->ssid_len != 0 &&
        (le32_to_cpu(scan_req->ssid_len) != vif->ssid_len ||
         memcmp(scan_req->ssid, vif->ssid, vif->ssid_len)))
        return;

    skb = dev_alloc_skb(len);
    if (!skb)
        return;

    skb_put(skb, len);

    eth = (struct ethhdr *) skb->data;
    memcpy(eth->h_dest, src, ETH_ALEN);
    memcpy(eth->h_source, vif->ndev->dev_addr, ETH_ALEN);

    /* We treat our management frame as 802.3 type, so we put length here */
    eth->h_proto = htons(len);

    vvh = (struct vwifi_virtio_header *) (eth + 1);
    vvh->type = cpu_to_le16(VWIFI_SCAN_RESPONSE);

    scan_resp =
        (struct vwifi_virtio_scan_resp *) ((u8 *) vvh +
                                           VWIFI_VIRTIO_HEADER_TYPE_BYTE);
    memcpy(scan_resp->bssid, vif->bssid, ETH_ALEN);
    scan_resp->timestamp = cpu_to_le64(div_u64(ktime_get_boottime_ns(), 1000));
    scan_resp->beacon_int = cpu_to_le16(100);
    scan_resp->capab_info = cpu_to_le16(WLAN_CAPABILITY_ESS);
    scan_resp->capab_info |=
        vif->privacy ? cpu_to_le16(WLAN_CAPABILITY_PRIVACY) : 0;
    scan_resp->ssid_len = cpu_to_le32(vif->ssid_len);
    memcpy(scan_resp->ssid, vif->ssid, vif->ssid_len);
    scan_resp->channel = cpu_to_le32(
        vif->wdev.wiphy->bands[NL80211_BAND_2GHZ]->channels[0].center_freq);
    scan_resp->beacon_ies_len = cpu_to_le32(vif->beacon_ie_len);
    memcpy(scan_resp->beacon_ies, vif->beacon_ie, vif->beacon_ie_len);

    vwifi_virtio_tx(vif, skb);
}


static void vwifi_virtio_mgmt_rx(struct vwifi_vif *vif, struct sk_buff *skb)
{
    struct ethhdr *eth = (struct ethhdr *) skb->data;
    struct vwifi_virtio_header *vh = (struct vwifi_virtio_header *) (eth + 1);

    switch (le16_to_cpu(vh->type)) {
    case VWIFI_SCAN_REQUEST:
        vwifi_virtio_mgmt_rx_scan_request(
            vif, eth->h_source,
            (struct vwifi_virtio_scan_req *) ((u8 *) vh +
                                              VWIFI_VIRTIO_HEADER_TYPE_BYTE));
        break;
    case VWIFI_SCAN_RESPONSE:
        vwifi_virtio_mgmt_rx_scan_response(
            vif, eth->h_source,
            (struct vwifi_virtio_scan_resp *) ((u8 *) vh +
                                               VWIFI_VIRTIO_HEADER_TYPE_BYTE));
        break;
    case VWIFI_CONNECT_REQUEST:
        vwifi_virtio_mgmt_rx_connect_request(
            vif, eth->h_source,
            (struct vwifi_virtio_conn_req *) ((u8 *) vh +
                                              VWIFI_VIRTIO_HEADER_TYPE_BYTE));
        break;
    case VWIFI_CONNECT_RESPONSE:
        vwifi_virtio_mgmt_rx_connect_response(
            vif, eth->h_source,
            (struct vwifi_virtio_conn_resp *) ((u8 *) vh +
                                               VWIFI_VIRTIO_HEADER_TYPE_BYTE));
        break;
    case VWIFI_DISCONNECT:
        vwifi_virtio_mgmt_rx_disconnect(
            vif, eth->h_source,
            (struct vwifi_virtio_disconn *) ((u8 *) vh +
                                             VWIFI_VIRTIO_HEADER_TYPE_BYTE));
        break;
    case VWIFI_STA_ENTRY_REQUEST:
        vwifi_virtio_mgmt_rx_sta_entry_request(vif, eth->h_source);
        break;
    case VWIFI_STA_ENTRY_RESPONSE:
        vwifi_virtio_mgmt_rx_sta_entry_response(
            vif, eth->h_source,
            (struct vwifi_virtio_sta_entry_resp
                 *) ((u8 *) vh + VWIFI_VIRTIO_HEADER_TYPE_BYTE));
        break;
    default:
        break;
    }

    dev_kfree_skb(skb);
}

static void vwifi_virtio_data_rx(struct vwifi_vif *vif, struct sk_buff *skb)
{
    struct ethhdr *eth = (struct ethhdr *) skb->data;
    struct bss_sta_entry *sta_ent;
    bool same_bss = false;

    mutex_lock(&vif->bss_sta_table_lock);
    hash_for_each_possible (vif->bss_sta_table, sta_ent, node,
                            vwifi_mac_to_32(eth->h_source)) {
        if (ether_addr_equal(sta_ent->mac, eth->h_source)) {
            same_bss = true;
            break;
        }
    }
    mutex_unlock(&vif->bss_sta_table_lock);

    /* We allow EAPOL frames to enter even when the sender is
     * not in the STA entry table.
     */
    if (!same_bss && eth->h_proto != htons(ETH_P_PAE))
        return;

    skb->dev = vif->ndev;
    skb->protocol = eth_type_trans(skb, vif->ndev);
    skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
    netif_rx_ni(skb);
#else
    netif_rx(skb);
#endif
}

static void vwifi_virtio_rx_switch(struct vwifi_vif *vif, struct sk_buff *skb)
{
    struct ethhdr *eth = (struct ethhdr *) skb->data;

    if (likely(eth_proto_is_802_3(eth->h_proto)))
        vwifi_virtio_data_rx(vif, skb);
    else
        vwifi_virtio_mgmt_rx(vif, skb);
}

static void vwifi_virtio_rx_work(struct work_struct *work)
{
    struct vwifi_vif *vif =
        list_first_entry(&vwifi->vif_list, struct vwifi_vif, list);
    struct sk_buff *skb;
    unsigned int len;
    unsigned long flags;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    if (!vwifi_virtio_enabled)
        goto out_unlock;

    skb = virtqueue_get_buf(vwifi_vqs[VWIFI_VQ_RX], &len);
    if (!skb)
        goto out_unlock;
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    skb_put(skb, len - vif->vnet_hdr_len);

    vwifi_virtio_rx_switch(vif, skb);

    vwifi_virtio_fill_vq(vwifi_vqs[VWIFI_VQ_RX], vif->vnet_hdr_len);

    schedule_work(&vwifi_virtio_rx);
    return;

out_unlock:
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
}

static void vwifi_virtio_tx_done(struct virtqueue *vq)
{
    struct sk_buff *skb;
    unsigned long flags;
    unsigned int len;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    while ((skb = virtqueue_get_buf(vq, &len)))
        dev_kfree_skb_irq(skb);
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
}

static void vwifi_virtio_rx_done(struct virtqueue *vq)
{
    schedule_work(&vwifi_virtio_rx);
}

static netdev_tx_t vwifi_virtio_tx(struct vwifi_vif *vif, struct sk_buff *skb)
{
    struct virtio_net_hdr_mrg_rxbuf *hdr =
        (struct virtio_net_hdr_mrg_rxbuf *) skb->cb;
    struct scatterlist sg[2];
    int err;
    unsigned long flags;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    if (!vwifi_virtio_enabled) {
        err = -ENODEV;
        goto out_free;
    }

    memset(hdr, 0, vif->vnet_hdr_len);
    hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
    hdr->hdr.flags = VIRTIO_NET_HDR_F_DATA_VALID;

    sg_init_table(sg, 2);
    sg_set_buf(sg, hdr, vif->vnet_hdr_len);
    sg_set_buf(sg + 1, skb->data, skb->len);

    err = virtqueue_add_outbuf(vwifi_vqs[VWIFI_VQ_TX], sg, 2, skb, GFP_ATOMIC);

    if (err)
        goto out_free;
    if (!virtqueue_kick(vwifi_vqs[VWIFI_VQ_TX])) {
        pr_info("%s: virtqueue_kick fail\n", __func__);
        goto out_free;
    }

    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
    return NETDEV_TX_OK;

out_free:
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
    dev_kfree_skb(skb);
    return err;
}

static int vwifi_virtio_init_vqs(struct virtio_device *vdev)
{
    vq_callback_t *callbacks[VWIFI_NUM_VQS] = {
        [VWIFI_VQ_RX] = vwifi_virtio_rx_done,
        [VWIFI_VQ_TX] = vwifi_virtio_tx_done,
    };
    const char *names[VWIFI_NUM_VQS] = {
        [VWIFI_VQ_RX] = "rx",
        [VWIFI_VQ_TX] = "tx",
    };

    return virtio_find_vqs(vdev, VWIFI_NUM_VQS, vwifi_vqs, callbacks, names,
                           NULL);
}

static void vwifi_virtio_fill_vq(struct virtqueue *vq, u8 vnet_hdr_len)
{
    struct sk_buff *skb;
    struct scatterlist sg[2];
    unsigned long flags;
    int err;

    skb = dev_alloc_skb(ETH_FRAME_LEN + NET_IP_ALIGN);
    if (!skb)
        return;

    /* align IP address on 16B boundary */
    skb_reserve(skb, NET_IP_ALIGN);

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    if (!vwifi_virtio_enabled)
        goto out_free;

    sg_init_table(sg, 2);
    sg_set_buf(sg, skb->cb, vnet_hdr_len);
    sg_set_buf(sg + 1, skb->data, ETH_FRAME_LEN);

    err = virtqueue_add_inbuf(vq, sg, 2, skb, GFP_ATOMIC);
    if (err)
        goto out_free;

    if (!virtqueue_kick(vq))
        goto out_free;

    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
    return;

out_free:
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
    dev_kfree_skb(skb);
}

static void vwifi_virtio_remove_vqs(struct virtio_device *vdev)
{
    int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
    virtio_reset_device(vdev);
#else
    vdev->config->reset(vdev);
#endif

    for (i = 0; i < ARRAY_SIZE(vwifi_vqs); i++) {
        struct virtqueue *vq = vwifi_vqs[i];
        struct sk_buff *skb;

        while ((skb = virtqueue_detach_unused_buf(vq)))
            dev_kfree_skb(skb);
    }

    vdev->config->del_vqs(vdev);
}

/* For now, we only support virtio when station=1 */
static int vwifi_virtio_probe(struct virtio_device *vdev)
{
    struct vwifi_vif *vif;
    unsigned long flags;
    int err;

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    if (vwifi_virtio_enabled) {
        spin_unlock_irqrestore(&vwifi_virtio_lock, flags);
        return -EEXIST;
    }
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    if (station != 1) {
        pr_info("virtio not enabled, please reload module with station=1\n");
        return -EINVAL;
    }

    vif = list_first_entry(&vwifi->vif_list, struct vwifi_vif, list);
    if (!vif)
        return -ENOENT;

    /* We assum VIRTIO_NET_F_MRG_RXBUF feature is off on the device */
    if (virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
        vif->vnet_hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
    else
        vif->vnet_hdr_len = sizeof(struct virtio_net_hdr);

    err = vwifi_virtio_init_vqs(vdev);
    if (err)
        return err;

    /* Configuration may specify what MAC to use.  Otherwise random. */
    if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC)) {
        u8 addr[ETH_ALEN];

        virtio_cread_bytes(vdev, offsetof(struct virtio_net_config, mac), addr,
                           ETH_ALEN);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        eth_hw_addr_set(vif->ndev, addr);
#else
        memcpy(vif->ndev->dev_addr, addr, ETH_ALEN);
#endif
    } else
        eth_hw_addr_random(vif->ndev);

    virtio_device_ready(vdev);

    spin_lock_irqsave(&vwifi_virtio_lock, flags);
    vwifi_virtio_enabled = true;
    spin_unlock_irqrestore(&vwifi_virtio_lock, flags);

    return 0;
}

static void vwifi_virtio_remove(struct virtio_device *vdev)
{
    vwifi_virtio_enabled = false;

    cancel_work_sync(&vwifi_virtio_rx);

    vwifi_virtio_remove_vqs(vdev);
}


/* vwifi virtio device id table */
static const struct virtio_device_id id_table[] = {
    {VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID},
    {0},
};
MODULE_DEVICE_TABLE(virtio, id_table);

static unsigned int features[] = {
    VIRTIO_NET_F_MAC,
};

static struct virtio_driver virtio_vwifi = {
    .feature_table = features,
    .feature_table_size = ARRAY_SIZE(features),
    .driver.name = KBUILD_MODNAME,
    .driver.owner = THIS_MODULE,
    .id_table = id_table,
    .probe = vwifi_virtio_probe,
    .remove = vwifi_virtio_remove,
};

static int __init vwifi_init(void)
{
    int err;

    vwifi = kmalloc(sizeof(struct vwifi_context), GFP_KERNEL);
    if (!vwifi) {
        pr_info("couldn't allocate space for vwifi_context\n");
        return -ENOMEM;
    }

    mutex_init(&vwifi->lock);
    INIT_LIST_HEAD(&vwifi->vif_list);
    INIT_LIST_HEAD(&vwifi->ap_list);
    vwifi->blocklist = kmalloc(sizeof(char) * MAX_BLACKLIST_SIZE, GFP_KERNEL);

    for (int i = 0; i < station; i++) {
        struct wiphy *wiphy = vwifi_cfg80211_add();
        if (!wiphy)
            goto cfg80211_add;
        if (!vwifi_interface_add(wiphy))
            goto interface_add;
    }

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &nl_config);
    if (!nl_sk) {
        pr_info("Error creating netlink socket\n");
        goto cfg80211_add;
    }

    err = register_virtio_driver(&virtio_vwifi);
    if (err)
        goto err_register_virtio_driver;

    vwifi->state = VWIFI_READY;

    return 0;

err_register_virtio_driver:
interface_add:
    /* FIXME: check for resource deallocation */
cfg80211_add:
    vwifi_free();

    return -1;
}

static void __exit vwifi_exit(void)
{
    vwifi->state = VWIFI_SHUTDOWN;

    unregister_virtio_driver(&virtio_vwifi);
    vwifi_free();
    netlink_kernel_release(nl_sk);
}

module_init(vwifi_init);
module_exit(vwifi_exit);
