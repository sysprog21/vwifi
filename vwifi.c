#include <linux/etherdevice.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/cfg80211.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("virtual cfg80211 driver");

#define NAME_PREFIX "owl"
#define NDEV_NAME NAME_PREFIX "%d"

#define MAX_PROBED_SSIDS 69

#ifndef DEFAULT_SSID_LIST
#define DEFAULT_SSID_LIST "[MyHomeWiFi]"
#endif

#define SCAN_TIMEOUT_MS 100 /*< millisecond */

struct owl_packet {
    int datalen;
    u8 data[ETH_DATA_LEN];
    struct list_head list;
};

/* Context for the whole program, so there's only single owl_context
 * no matter the number of virtual interfaces.
 * Fileds in the structure are interface-independent.
 */
struct owl_context {
    /* We may not need this lock, cause vif_list would not change during
     * the whole lifetime.
     */
    struct mutex lock;
    /* List head for maintain multiple network device private context */
    struct list_head vif_list;
};

/* SME stands for "station management entity" */
enum sme_state { SME_DISCONNECTED, SME_CONNECTING, SME_CONNECTED };

/* Virtual interface which is pointed by netdev_priv(). Fields in the
 * structure are interface-dependent.
 */
struct owl_vif {
    struct wireless_dev wdev;
    struct net_device *ndev;
    struct net_device_stats stats;

    /* Currently connected BSS id */
    u8 bssid[ETH_ALEN];
    u8 ssid[IEEE80211_MAX_SSID_LEN];
    /* For the case the STA is going to roam to another BSS */
    u8 req_bssid[ETH_ALEN];
    u8 req_ssid[IEEE80211_MAX_SSID_LEN];
    struct cfg80211_scan_request *scan_request;
    enum sme_state sme_state;  /* connection information */
    unsigned long conn_time;   /* last connection time to a AP (in jiffies) */
    unsigned long active_time; /* last tx/rx time (in jiffies) */
    u16 disconnect_reason_code;

    struct mutex lock;
    struct timer_list scan_timeout;
    struct work_struct ws_connect, ws_disconnect;
    struct work_struct ws_scan, ws_scan_timeout;
    struct list_head rx_queue; /* Head of received packet queue */

    /* List entry for maintaining multiple private data of net_device in
     * owl_context.vif_list.
     */
    struct list_head list;
};

/* AP information table entry */
struct ap_info_entry_t {
    struct hlist_node node;
    u8 bssid[ETH_ALEN];
    char ssid[IEEE80211_MAX_SSID_LEN];
};

static char *ssid_list = DEFAULT_SSID_LIST;
module_param(ssid_list, charp, 0644);
MODULE_PARM_DESC(ssid_list, "Self-defined SSIDs.");

static int interfaces = 2;
module_param(interfaces, int, 0444);
MODULE_PARM_DESC(interfaces, "Number of virtual interfaces.");

/* AP database */
static DECLARE_HASHTABLE(ssid_table, 4);

/* Global context */
static struct owl_context *owl = NULL;

/* helper function to retrieve vif from net_device */
static inline struct owl_vif *ndev_get_owl_vif(struct net_device *ndev)
{
    return (struct owl_vif *) netdev_priv(ndev);
}

/* helper function to retrieve vif from wireless_dev */
static inline struct owl_vif *wdev_get_owl_vif(struct wireless_dev *wdev)
{
    return container_of(wdev, struct owl_vif, wdev);
}

#define SIN_S3_MIN (-(1 << 12))
#define SIN_S3_MAX (1 << 12)
/* A sine approximation via a third-order approx.
 * https://www.coranac.com/2009/07/sines explain the
 * details about the magic inside this function. I adjusted
 * some parameter to make the frequency of the sine function
 * larger.
 * __sin_s3() is for internal use of rand_int_smooth(), never
 * call this function elsewhere.
 * @x: seed to generate third-order sine value
 * @return: signed 32-bit integer ranging from SIN_S3_MIN ~ SIN_S3_MAX
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

/* Generate a signed 32-bit integer by feeding seed into
 * __sin_s3(). It's closer to a sine function if you plot
 * the distribution of (seed, rand_int_smmoth()).
 */
static inline s32 rand_int_smooth(s32 low, s32 up, s32 seed)
{
    s32 result = __sin_s3(seed) - SIN_S3_MIN;
    result = (result * (up - low)) / (SIN_S3_MAX - SIN_S3_MIN);
    result += low;
    return result;
}

/* Murmur hash.
 * See https://stackoverflow.com/a/57960443
 */
static inline uint64_t murmurhash(const char *str)
{
    uint64_t h = 525201411107845655ull;
    for (; *str; ++str) {
        h ^= *str;
        h *= 0x5bd1e9955bd1e995;
        h ^= h >> 47;
    }
    return h;
}

/* Helper function for generating BSSID from SSID */
static void generate_bssid_with_ssid(u8 *result, const char *ssid)
{
    u64_to_ether_addr(murmurhash(ssid), result);
    result[0] &= 0xfe; /* clear multicast bit */
    result[0] |= 0x02; /* set local assignment bit */
}

/* Update AP database from module parameter ssid_list */
static void update_ssids(const char *ssid_list)
{
    struct ap_info_entry_t *ap;
    const char delims[] = "[]";
    struct hlist_node *tmp;

    for (char *s = (char *) ssid_list; *s != 0; /*empty*/) {
        bool ssid_exist = false;
        char token[IEEE80211_MAX_SSID_LEN] = {0};

        /* Get the number of token separator characters. */
        size_t n = strspn(s, delims);
        s += n; /* Actually skip the separators */
        /* Get the number of token (non-separator) characters. */
        n = strcspn(s, delims);
        if (n == 0)  // token not found
            continue;
        strncpy(token, s, n);
        s += n; /* Point the next token */

        /* Insert the SSID into hash */
        token[n] = '\0';
        u32 key = murmurhash((char *) token);
        hash_for_each_possible_safe (ssid_table, ap, tmp, node, key) {
            if (strncmp(token, ap->ssid, n) == 0) {
                ssid_exist = true;
                break;
            }
        }
        if (ssid_exist) /* SSID exists */
            continue;

        ap = kzalloc(sizeof(struct ap_info_entry_t), GFP_KERNEL);
        if (!ap) {
            pr_err("Failed to alloc ap_info_entry_t incomming SSID=%s\n",
                   token);
            return;
        }
        u8 bssid[ETH_ALEN] = {0};
        strncpy(ap->ssid, token, n);
        generate_bssid_with_ssid(bssid, token);
        memcpy(ap->bssid, bssid, ETH_ALEN);
        hash_add(ssid_table, &ap->node, key);
    }
}

/* Helper function that will prepare structure with self-defined BSS information
 * and "inform" the kernel about "new" BSS Most of the code are copied from the
 * upcoming inform_dummy_bss function.
 */
static void inform_dummy_bss(struct owl_vif *vif)
{
    struct ap_info_entry_t *ap;
    int i;
    struct hlist_node *tmp;

    update_ssids(ssid_list);
    if (hash_empty(ssid_table))
        return;

    hash_for_each_safe (ssid_table, i, tmp, ap, node) {
        struct cfg80211_bss *bss = NULL;
        struct cfg80211_inform_bss data = {
            /* the only channel */
            .chan = &vif->wdev.wiphy->bands[NL80211_BAND_2GHZ]->channels[0],
            .scan_width = NL80211_BSS_CHAN_WIDTH_20,
            .signal = rand_int_smooth(-100, -30, jiffies) * 100,
        };

        size_t ssid_len = strlen(ap->ssid);
        u8 *ie = kmalloc((ssid_len + 3) * sizeof(ie), GFP_KERNEL);
        ie[0] = WLAN_EID_SSID;
        ie[1] = ssid_len;
        memcpy(ie + 2, ap->ssid, ssid_len);

        /* Using CLOCK_BOOTTIME clock, which won't be affected by
         * changes in system time-of-day clock, and includes any time
         * that the system is suspended. Thus, it's suitable for
         * tsf to synchronize the machines in BSS.
         */
        u64 tsf = div_u64(ktime_get_boottime_ns(), 1000);

        /* It is posible to use cfg80211_inform_bss() instead. */
        bss = cfg80211_inform_bss_data(
            vif->wdev.wiphy, &data, CFG80211_BSS_FTYPE_UNKNOWN, ap->bssid, tsf,
            WLAN_CAPABILITY_ESS, 100, ie, ssid_len + 2, GFP_KERNEL);

        /* cfg80211_inform_bss_data() returns cfg80211_bss structure referefence
         * counter of which should be decremented if it is unused.
         */
        cfg80211_put_bss(vif->wdev.wiphy, bss);
        kfree(ie);
    }
}

static int owl_ndo_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

static int owl_ndo_stop(struct net_device *dev)
{
    struct owl_vif *vif = ndev_get_owl_vif(dev);
    struct owl_packet *pkt, *is = NULL;
    list_for_each_entry_safe (pkt, is, &vif->rx_queue, list) {
        list_del(&pkt->list);
        kfree(pkt);
    }
    netif_stop_queue(dev);
    return 0;
}

static struct net_device_stats *owl_ndo_get_stats(struct net_device *dev)
{
    struct owl_vif *vif = ndev_get_owl_vif(dev);
    return &vif->stats;
}

/* Receive a packet: retrieve, encapsulate and pass over to upper levels */
static void owl_rx(struct net_device *dev)
{
    struct owl_vif *vif = ndev_get_owl_vif(dev);
    struct sk_buff *skb;
    char prefix[16];
    struct owl_packet *pkt;

    if (list_empty(&vif->rx_queue)) {
        printk(KERN_NOTICE "owl rx: No packet in rx_queue\n");
        return;
    }

    if (mutex_lock_interruptible(&vif->lock))
        goto pkt_free;

    pkt = list_first_entry(&vif->rx_queue, struct owl_packet, list);
    mutex_unlock(&vif->lock);

    vif->stats.rx_packets++;
    vif->stats.rx_bytes += pkt->datalen;
    vif->active_time = jiffies;

    snprintf(prefix, 16, "%s Rx ", dev->name);
    print_hex_dump(KERN_DEBUG, prefix, DUMP_PREFIX_OFFSET, 16, 1, pkt->data,
                   pkt->datalen, false);
    /* Put raw packet into socket buffer */
    skb = dev_alloc_skb(pkt->datalen + 2);
    if (!skb) {
        printk(KERN_NOTICE "owl rx: low on mem - packet dropped\n");
        vif->stats.rx_dropped++;
        goto pkt_free;
    }
    skb_reserve(skb, 2); /* align IP on 16B boundary */
    memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

    /* Write metadata, and then pass to the receive level */
    skb->dev = dev;
    skb->protocol = eth_type_trans(skb, dev);
    skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
    netif_rx(skb);

pkt_free:
    list_del(&pkt->list);
    kfree(pkt);
}

static int __owl_ndo_start_xmit(struct owl_vif *vif,
                                struct owl_vif *dest_vif,
                                struct sk_buff *skb)
{
    struct owl_packet *pkt = NULL;

    pkt = kmalloc(sizeof(struct owl_packet), GFP_KERNEL);
    if (!pkt) {
        printk(KERN_NOTICE "Ran out of memory allocating packet pool\n");
        return NETDEV_TX_OK;
    }
    memcpy(pkt->data, skb->data, skb->len);
    pkt->datalen = skb->len;

    char prefix[16];
    snprintf(prefix, 16, "%s Tx ", vif->ndev->name);
    print_hex_dump(KERN_DEBUG, prefix, DUMP_PREFIX_OFFSET, 16, 1, pkt->data,
                   pkt->datalen, false);

    /* enqueue packet to destination vif's rx_queue */
    if (mutex_lock_interruptible(&dest_vif->lock))
        goto l_error_mutex_lock;
    list_add_tail(&pkt->list, &dest_vif->rx_queue);
    mutex_unlock(&dest_vif->lock);

    /* Update interface statistics */
    vif->stats.tx_packets++;
    vif->stats.tx_bytes += pkt->datalen;
    vif->active_time = jiffies;

    /* Directly send to rx_queue, simulate the rx interrupt */
    owl_rx(dest_vif->ndev);

    return 0;

l_error_mutex_lock:
    kfree(pkt);
    vif->stats.tx_dropped++;
    return -1;
}

/* Network packet transmit.
 * Callback called by the kernel when packet of data should be sent.
 * In this example it does nothing.
 */
static netdev_tx_t owl_ndo_start_xmit(struct sk_buff *skb,
                                      struct net_device *dev)
{
    printk(KERN_INFO "owl: ndo_start_xmit\n");

    struct owl_vif *vif = ndev_get_owl_vif(dev);
    struct owl_vif *dest_vif = NULL;
    struct ethhdr *eth_hdr = NULL;
    int count = 0;

    eth_hdr = (struct ethhdr *) skb->data;
    /* Check if the packet is broadcasting */
    if (is_broadcast_ether_addr(eth_hdr->h_dest)) {
        list_for_each_entry (dest_vif, &owl->vif_list, list) {
            if (dest_vif == vif)
                continue;
            __owl_ndo_start_xmit(vif, dest_vif, skb);
            count++;
        }
    }
    /* The packet is unicasting */
    else {
        list_for_each_entry (dest_vif, &owl->vif_list, list) {
            if (ether_addr_equal(eth_hdr->h_dest, dest_vif->ndev->dev_addr)) {
                __owl_ndo_start_xmit(vif, dest_vif, skb);
                count++;
                break;
            }
        }
    }

    if (!count)
        vif->stats.tx_dropped++;

    /* Don't forget to cleanup skb, as its ownership moved to xmit callback. */
    kfree_skb(skb);

    return NETDEV_TX_OK;
}

/* Structure of functions for network devices.
 * It should have at least ndo_start_xmit functions called for packet to be
 * sent.
 */
static struct net_device_ops owl_ndev_ops = {
    .ndo_open = owl_ndo_open,
    .ndo_stop = owl_ndo_stop,
    .ndo_start_xmit = owl_ndo_start_xmit,
    .ndo_get_stats = owl_ndo_get_stats,
};

/* Inform the "dummy" BSS to kernel and call cfg80211_scan_done() to finish
 * scan.
 */
static void owl_scan_timeout_work(struct work_struct *w)
{
    struct owl_vif *vif = container_of(w, struct owl_vif, ws_scan_timeout);
    struct cfg80211_scan_info info = {
        /* if scan was aborted by user (calling cfg80211_ops->abort_scan) or by
         * any driver/hardware issue - field should be set to "true"
         */
        .aborted = false,
    };

    /* inform with dummy BSS */
    inform_dummy_bss(vif);

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
static void owl_scan_timeout(struct timer_list *t)
{
    struct owl_vif *vif = container_of(t, struct owl_vif, scan_timeout);

    if (vif->scan_request)
        schedule_work(&vif->ws_scan_timeout);
}

/* "Scan routine". It simulates a fake BSS scan (In fact, do nothing.), and sets
 * a scan timer to start from then. Once the timer timeouts, the timeout
 * routine owl_scan_timeout() will be invoked, which schedules a timeout work,
 * and the timeout work will inform the kernel about "dummy" BSS and finish the
 * scan.
 */
static void owl_scan_routine(struct work_struct *w)
{
    struct owl_vif *vif = container_of(w, struct owl_vif, ws_scan);

    /* In real world driver, we scan BSS here. But viwifi doesn't, because we
     * already store dummy BSS in ssid hash table. So we just set a scan timeout
     * after specific jiffies, and inform "dummy" BSS to kernel and call
     * cfg80211_scan_done() by timeout worker.
     */
    mod_timer(&vif->scan_timeout, jiffies + msecs_to_jiffies(SCAN_TIMEOUT_MS));
}

/* It checks SSID of the ESS to connect and informs the kernel that connection
 * is finished. It should call cfg80211_connect_bss() when connect is finished
 * or cfg80211_connect_timeout() when connect is failed. This module can connect
 * only to ESS with SSID equal to SSID_DUMMY value.
 * This routine is called through workqueue, when the kernel asks to connect
 * through cfg80211_ops.
 */
static bool is_valid_ssid(const char *connecting_ssid)
{
    bool is_valid = false;
    struct ap_info_entry_t *ap;
    struct hlist_node *tmp;

    u32 key = murmurhash((char *) connecting_ssid);
    hash_for_each_possible_safe (ssid_table, ap, tmp, node, key) {
        if (!strcmp(connecting_ssid, ap->ssid)) {
            is_valid = true;
            break;
        }
    }

    return is_valid;
}

static void get_connecting_bssid(const char *connecting_ssid,
                                 u8 *connecting_bssid)
{
    struct ap_info_entry_t *ap;
    struct hlist_node *tmp;
    u32 key = murmurhash((char *) connecting_ssid);
    hash_for_each_possible_safe (ssid_table, ap, tmp, node, key) {
        if (!strcmp(connecting_ssid, ap->ssid)) {
            memcpy(connecting_bssid, ap->bssid, ETH_ALEN);
            break;
        }
    }
}

static void owl_connect_routine(struct work_struct *w)
{
    struct owl_vif *vif = container_of(w, struct owl_vif, ws_connect);

    if (mutex_lock_interruptible(&vif->lock))
        return;

    if (!is_valid_ssid(vif->req_ssid)) {
        cfg80211_connect_timeout(vif->ndev, NULL, NULL, 0, GFP_KERNEL,
                                 NL80211_TIMEOUT_SCAN);
        vif->sme_state = SME_DISCONNECTED;
    } else {
        /* It is possible to use cfg80211_connect_result() or
         * cfg80211_connect_done()
         */
        cfg80211_connect_result(vif->ndev, NULL, NULL, 0, NULL, 0,
                                WLAN_STATUS_SUCCESS, GFP_KERNEL);
        memcpy(vif->ssid, vif->req_ssid, IEEE80211_MAX_SSID_LEN);
        memcpy(vif->bssid, vif->req_bssid, ETH_ALEN);
        vif->sme_state = SME_CONNECTED;
        vif->conn_time = jiffies;
    }

    memset(vif->req_ssid, 0, IEEE80211_MAX_SSID_LEN);
    memset(vif->req_bssid, 0, ETH_ALEN);
    mutex_unlock(&vif->lock);
}

/* Invoke cfg80211_disconnected() that informs the kernel that disconnect is
 * complete. Overall disconnect may call cfg80211_connect_timeout() if
 * disconnect interrupting connection routine, but for this module let's keep
 * it simple as possible. This routine is called through workqueue, when the
 * kernel asks to disconnect through cfg80211_ops.
 */
static void owl_disconnect_routine(struct work_struct *w)
{
    struct owl_vif *vif = container_of(w, struct owl_vif, ws_disconnect);

    if (mutex_lock_interruptible(&vif->lock))
        return;

    cfg80211_disconnected(vif->ndev, vif->disconnect_reason_code, NULL, 0, true,
                          GFP_KERNEL);
    vif->disconnect_reason_code = 0;
    vif->sme_state = SME_DISCONNECTED;

    mutex_unlock(&vif->lock);
}

/* callback called by the kernel when user decided to scan.
 * This callback should initiate scan routine(through work_struct) and exit with
 * 0 if everything is ok.
 */
static int owl_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request)
{
    struct owl_vif *vif = wdev_get_owl_vif(request->wdev);

    printk(KERN_INFO "owl: owl_scan\n");
    for (int i = 0; i < request->n_ssids; i++)
        printk("owl: request ssid[%d] = %s\n", i, request->ssids[i].ssid);

    if (mutex_lock_interruptible(&vif->lock))
        return -ERESTARTSYS;

    if (vif->scan_request) {
        mutex_unlock(&vif->lock);
        return -EBUSY;
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
static int owl_connect(struct wiphy *wiphy,
                       struct net_device *dev,
                       struct cfg80211_connect_params *sme)
{
    struct owl_vif *vif = ndev_get_owl_vif(dev);

    printk(KERN_INFO "owl: owl_connect\n");

    if (mutex_lock_interruptible(&vif->lock))
        return -ERESTARTSYS;

    vif->sme_state = SME_CONNECTING;
    memcpy(vif->req_ssid, sme->ssid, IEEE80211_MAX_SSID_LEN);
    get_connecting_bssid(vif->req_ssid, vif->req_bssid);
    mutex_unlock(&vif->lock);

    if (!schedule_work(&vif->ws_connect))
        return -EBUSY;
    return 0;
}

/* callback called by the kernel when there is need to "diconnect" from
 * currently connected network. It initializes disconnect routine through
 * work_struct and exits with 0 if everything ok. disconnect routine should
 * call cfg80211_disconnected() to inform the kernel that disconnection is
 * complete.
 */
static int owl_disconnect(struct wiphy *wiphy,
                          struct net_device *dev,
                          u16 reason_code)
{
    struct owl_vif *vif = ndev_get_owl_vif(dev);

    if (mutex_lock_interruptible(&vif->lock))
        return -ERESTARTSYS;

    vif->disconnect_reason_code = reason_code;

    mutex_unlock(&vif->lock);

    if (!schedule_work(&vif->ws_disconnect))
        return -EBUSY;

    return 0;
}

/* Callback called by kernel when user decided to get
 * informations of a specific station. The informations
 * include numbers and bytes of tx/rx, signal, and
 * timing informations (inactive time and elapsed time since
 * the last connection to an AP).
 * Called when rtnl lock was acquired.
 */
static int owl_get_station(struct wiphy *wiphy,
                           struct net_device *dev,
                           const u8 *mac,
                           struct station_info *sinfo)
{
    struct owl_vif *vif = NULL;

    /* Find the station which is being searched */
    list_for_each_entry (vif, &owl->vif_list, list) {
        if (ether_addr_equal(vif->ndev->dev_addr, mac)) {
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
            }

            sinfo->tx_packets = vif->stats.tx_packets;
            sinfo->rx_packets = vif->stats.rx_packets;
            sinfo->tx_failed = vif->stats.tx_dropped;
            sinfo->tx_bytes = vif->stats.tx_bytes;
            sinfo->rx_bytes = vif->stats.rx_bytes;
            /* For CFG80211_SIGNAL_TYPE_MBM, value is expressed in dbm */
            sinfo->signal = rand_int_smooth(-100, -30, jiffies);
            sinfo->inactive_time = jiffies_to_msecs(jiffies - vif->active_time);

            return 0;
        }
    }
    return -ENOENT;
}

/* Create a virtual interface, which owns a wiphy which is not shared
 * with other interfaces. Interface mode is set to STA mode, who wants
 * to change the interface type should call change_virtual_intf().
 */
static struct wireless_dev *owl_interface_add(struct wiphy *wiphy, int if_idx)
{
    struct net_device *ndev = NULL;
    struct owl_vif *vif = NULL;

    /* allocate network device context. */
    ndev = alloc_netdev(sizeof(struct owl_vif), NDEV_NAME, NET_NAME_ENUM,
                        ether_setup);

    if (!ndev)
        goto l_error_alloc_ndev;

    /* fill private data of network context. */
    vif = ndev_get_owl_vif(ndev);
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
    vif->ndev->netdev_ops = &owl_ndev_ops;

    /* Add here proper net_device initialization */
    vif->ndev->features |= NETIF_F_HW_CSUM;

    /* The first byte is '\0' to avoid being a multicast
     * address (the first byte of multicast addrs is odd).
     */
    char intf_name[ETH_ALEN] = {0};
    snprintf(intf_name + 1, ETH_ALEN, "%s%d", NAME_PREFIX, if_idx);
    memcpy(vif->ndev->dev_addr, intf_name, ETH_ALEN);

    /* register network device. If everything is ok, there should be new
     * network device: $ ip a owl0: <BROADCAST,MULTICAST> mtu 1500 qdisc
     * noop state DOWN group default link/ether 00:00:00:00:00:00 brd
     * ff:ff:ff:ff:ff:ff
     */
    if (register_netdev(vif->ndev))
        goto l_error_ndev_register;

    /* Initialize connection information */
    memset(vif->bssid, 0, ETH_ALEN);
    memset(vif->ssid, 0, IEEE80211_MAX_SSID_LEN);
    memset(vif->req_bssid, 0, ETH_ALEN);
    memset(vif->req_ssid, 0, IEEE80211_MAX_SSID_LEN);
    vif->scan_request = NULL;
    vif->sme_state = SME_DISCONNECTED;
    vif->conn_time = 0;
    vif->active_time = 0;
    vif->disconnect_reason_code = 0;

    mutex_init(&vif->lock);

    /* Initialize timer of scan_timeout */
    timer_setup(&vif->scan_timeout, owl_scan_timeout, 0);

    INIT_WORK(&vif->ws_connect, owl_connect_routine);
    INIT_WORK(&vif->ws_disconnect, owl_disconnect_routine);
    INIT_WORK(&vif->ws_scan, owl_scan_routine);
    INIT_WORK(&vif->ws_scan_timeout, owl_scan_timeout_work);

    /* Initialize rx_queue */
    INIT_LIST_HEAD(&vif->rx_queue);

    /* Add vif into global vif_list */
    if (mutex_lock_interruptible(&owl->lock))
        goto l_error_add_list;
    list_add_tail(&vif->list, &owl->vif_list);
    mutex_unlock(&owl->lock);

    return &vif->wdev;

l_error_add_list:
    unregister_netdev(vif->ndev);
l_error_ndev_register:
    free_netdev(vif->ndev);
l_error_alloc_ndev:
    wiphy_unregister(wiphy);
    wiphy_free(wiphy);
    return NULL;
}

/* Unregister and free a virtual interface identified by @vif->ndev. */
static int owl_delete_interface(struct owl_vif *vif)
{
    struct owl_packet *pkt = NULL, *safe = NULL;
    struct wiphy *wiphy = vif->ndev->ieee80211_ptr->wiphy;

    if (mutex_lock_interruptible(&owl->lock))
        return -ERESTARTSYS;

    list_del(&vif->list);
    mutex_unlock(&owl->lock);

    /* Stop TX queue, and delete the pending packets */
    netif_stop_queue(vif->ndev);
    list_for_each_entry_safe (pkt, safe, &vif->rx_queue, list) {
        list_del(&pkt->list);
        kfree(pkt);
    }
    /* If there's is a pending scan, call cfg80211_scan_done to finish it. */
    if (vif->scan_request) {
        struct cfg80211_scan_info info = {
            .aborted = true,
        };

        cfg80211_scan_done(vif->scan_request, &info);
        vif->scan_request = NULL;
    }

    /* Make sure that no work is queued */
    del_timer_sync(&vif->scan_timeout);
    cancel_work_sync(&vif->ws_connect);
    cancel_work_sync(&vif->ws_disconnect);
    cancel_work_sync(&vif->ws_scan);
    cancel_work_sync(&vif->ws_scan_timeout);

    /* Deallocate net_device */
    unregister_netdev(vif->ndev);
    free_netdev(vif->ndev);

    /* Deallocate wiphy device */
    wiphy_unregister(wiphy);
    wiphy_free(wiphy);

    return 0;
}

/* Structure of functions for FullMAC 80211 drivers.
 * Functions implemented along with fields/flags in wiphy structure would
 * represent drivers features. This module can only perform "scan" and
 * "connect". Some functions cant be implemented alone, for example: with
 * "connect" there is should be function "disconnect".
 */
static struct cfg80211_ops owl_cfg_ops = {
    .scan = owl_scan,
    .connect = owl_connect,
    .disconnect = owl_disconnect,
    .get_station = owl_get_station,
};

/* Array of "supported" channels in 2GHz band. It is required for wiphy.
 * For demo - the only channel 6.
 */
static struct ieee80211_channel owl_supported_channels_2ghz[] = {
    {
        .band = NL80211_BAND_2GHZ,
        .hw_value = 6,
        .center_freq = 2437,
    },
};

/* Array of supported rates, required to support at least those next rates
 * for 2GHz band.
 */
static struct ieee80211_rate owl_supported_rates_2ghz[] = {
    {
        .bitrate = 10,
        .hw_value = 0x1,
    },
    {
        .bitrate = 20,
        .hw_value = 0x2,
    },
    {
        .bitrate = 55,
        .hw_value = 0x4,
    },
    {
        .bitrate = 110,
        .hw_value = 0x8,
    },
};

/* Describes supported band of 2GHz. */
static struct ieee80211_supported_band nf_band_2ghz = {
    /* FIXME: add other band capabilities if nedded, such as 40 width */
    .ht_cap.cap = IEEE80211_HT_CAP_SGI_20,
    .ht_cap.ht_supported = false,

    .channels = owl_supported_channels_2ghz,
    .n_channels = ARRAY_SIZE(owl_supported_channels_2ghz),

    .bitrates = owl_supported_rates_2ghz,
    .n_bitrates = ARRAY_SIZE(owl_supported_rates_2ghz),
};

/* Unregister and free virtual interfaces and wiphy. */
static void owl_free(void)
{
    struct owl_vif *vif = NULL, *safe = NULL;

    list_for_each_entry_safe (vif, safe, &owl->vif_list, list)
        owl_delete_interface(vif);
}

/* Allocate and register wiphy.
 * Virtual interfaces should be created by nl80211, which will
 * call cfg80211_ops->add_iface(). This program create a wiphy
 * for every virtual interface, which means an virtual interface
 * has an physical (virtual) adapter under it.
 */
static struct wiphy *owl_cfg80211_add(void)
{
    struct wiphy *wiphy = NULL;

    /* allocate wiphy context. It is possible just to use wiphy_new().
     * wiphy should represent physical FullMAC wireless device. We need
     * to implement add_virtual_intf() from cfg80211_ops for adding
     * interface(s) on top of a wiphy.
     * NULL means use the default phy%d naming.
     */
    wiphy = wiphy_new_nm(&owl_cfg_ops, 0, NULL);
    if (!wiphy) {
        printk(KERN_INFO "couldn't allocate wiphy device\n");
        return NULL;
    }

    /* FIXME: set device object as wiphy "parent" */
    /* set_wiphy_dev(ret->wiphy, dev); */

    /* wiphy should determinate its type.
     * add other required types like  "BIT(NL80211_IFTYPE_STATION) |
     * BIT(NL80211_IFTYPE_AP)" etc.
     */
    wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

    /* wiphy should have at least 1 band.
     * Also fill NL80211_BAND_5GHZ if required. In this module, only 1 band
     * with 1 "channel"
     */
    wiphy->bands[NL80211_BAND_2GHZ] = &nf_band_2ghz;

    /* scan - if the device supports "scan", we need to define max_scan_ssids
     * at least.
     */
    wiphy->max_scan_ssids = MAX_PROBED_SSIDS;

    /* Signal type
     * CFG80211_SIGNAL_TYPE_UNSPEC allows us specify signal strength from 0 to
     * 100. The reasonable value for CFG80211_SIGNAL_TYPE_MBM is -3000 to -10000
     * (mdBm).
     */
    wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

    wiphy->flags |= WIPHY_FLAG_NETNS_OK;

    /* zegister wiphy, if everything ok - there should be another wireless
     * device in system. use command: $ iw list
     * Wiphy owl
     */
    if (wiphy_register(wiphy) < 0) {
        printk(KERN_INFO "couldn't register wiphy device\n");
        goto l_error_wiphy_register;
    }

    return wiphy;

l_error_wiphy_register:
    wiphy_free(wiphy);
    return NULL;
}

static int __init vwifi_init(void)
{
    owl = kmalloc(sizeof(struct owl_context), GFP_KERNEL);
    if (!owl) {
        printk("couldn't allocate space for owl_context\n");
        return -ENOMEM;
    }

    mutex_init(&owl->lock);
    INIT_LIST_HEAD(&owl->vif_list);

    for (int i = 0; i < interfaces; i++) {
        struct wiphy *wiphy = owl_cfg80211_add();
        if (!wiphy)
            goto l_cfg80211_add;
        if (!owl_interface_add(wiphy, i))
            goto l_interface_add;
    }

    return 0;

l_interface_add:
l_cfg80211_add:
    owl_free();
    return -1;
}

static void __exit vwifi_exit(void)
{
    owl_free();
}

module_init(vwifi_init);
module_exit(vwifi_exit);
