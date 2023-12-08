#include <getopt.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_PAYLOAD 1024
#define LINE_LENGTH 20
#define MAX_BLOCKLIST_PAIR 5
#define VWIFI_STATUS_FILE "/sys/module/vwifi/initstate"


/* The function aims to check the status of vwifi kernel module */
bool vwifi_status_check()
{
    FILE *fp = fopen(VWIFI_STATUS_FILE, "r");
    if (!fp) {
        printf("vwifi status : not loaded\n");
        return false;
    }

    char read_buf[LINE_LENGTH];
    fgets(read_buf, LINE_LENGTH, fp);
    read_buf[strcspn(read_buf, "\n")] =
        0; /* Remove newline character from string */
    if (!strcmp("live", read_buf))
        printf("vwifi status : live\n");
    else {
        printf("vwifi status : %s\n", read_buf);
        return false;
    }
    return true;
}

/* Check if command line options are specified */
bool opt_set(int d, int s, int c)
{
    return d || s || c;
}

/* Check whether the number of source interfaces matches with the number of
 * destination interfaces */
bool blocklist_pair_check(int src_len, int dest_len)
{
    return src_len == dest_len;
}

/* Copy destination and source interface pair into blocklist buffer */
bool blocklist_make(char *blocklist,
                    char *dest[],
                    char *src[],
                    int blocklist_len)
{
    for (int i = 0; i < blocklist_len; i++) {
        char tmp[LINE_LENGTH] = {'\0'};
        snprintf(tmp, LINE_LENGTH, "%s %s %s\n", dest[i], "blocks", src[i]);
        if (strlen(tmp) + strlen(blocklist) < NLMSG_SPACE(MAX_PAYLOAD))
            strcat(blocklist, tmp);
        else {
            printf(
                "Error: Blocklist size exceeds the maximum size of buffer\n");
            return false;
        }
    }
    return true;
}

/* Send blocklist to kernel using netlink socket */
bool blocklist_send(char *blocklist)
{
    int sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock_fd < 0) {
        printf("Error: Can't open socket\n");
        return false;
    }

    struct sockaddr_nl src_addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid(),
    };

    bind(sock_fd, (struct sockaddr *) &src_addr, sizeof(src_addr));

    struct sockaddr_nl dest_addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
    };

    struct nlmsghdr *nlh =
        (struct nlmsghdr *) calloc(1, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strncpy(NLMSG_DATA(nlh), blocklist, NLMSG_SPACE(MAX_PAYLOAD));

    struct iovec iov = {
        .iov_base = (void *) nlh,
        .iov_len = nlh->nlmsg_len,
    };

    struct msghdr msg = {
        .msg_name = (void *) &dest_addr,
        .msg_namelen = sizeof(dest_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    printf("Configuring blocklist for vwifi...\n");
    sendmsg(sock_fd, &msg, 0);

    recvmsg(sock_fd, &msg, 0);
    printf("Message from vwifi: %s\n", (char *) NLMSG_DATA(nlh));

    close(sock_fd);

    return true;
}

int main(int argc, char *argv[])
{
    /* Get opt arguments from command line to configure blocklist */
    char *dest[MAX_BLOCKLIST_PAIR], *src[MAX_BLOCKLIST_PAIR],
        blocklist_pair[MAX_BLOCKLIST_PAIR][LINE_LENGTH];
    int blocklist_len = 0, dest_len = 0, src_len = 0, clear = 0;
    int c;

    while ((c = getopt(argc, argv, "d:s:ch")) != -1) {
        switch (c) {
        case 'd':
            dest[dest_len++] = optarg;
            break;
        case 's':
            src[src_len++] = optarg;
            break;
        case 'c':
            clear = 1;
            break;
        case 'h':
            printf(
                "vwifi-tool: A userspace tool which supports more "
                "user-specific utilization for vwifi\n\n");
            printf("Usage:\n\n");
            printf("\tvwifi-tool [arguments]\n\n");
            printf("The arguments are:\n\n");
            printf("\t-d  Destination interface name\n");
            printf("\t-s Source interface name\n");
            printf("\t-c Clear blocklist\n");
            return 0;
        default:
            printf("Invalid arguments\n");
            break;
        }
    }

    if (!vwifi_status_check())
        exit(1);

    /* When no options are specified, simply display the status of vwifi */
    if (!opt_set(dest_len, src_len, clear))
        return 0;

    if (!clear && !blocklist_pair_check(src_len, dest_len)) {
        printf("Destination number doesn't match with Source number\n");
        exit(1);
    }

    blocklist_len =
        clear ? 0
              : (dest_len < MAX_BLOCKLIST_PAIR ? dest_len : MAX_BLOCKLIST_PAIR);

    /* Copy blocklist pair into message buffer */
    char buffer[NLMSG_SPACE(MAX_PAYLOAD)];
    memset(buffer, '\0', sizeof(buffer));

    if (!blocklist_make(buffer, dest, src, blocklist_len))
        exit(1);

    if (!clear)
        printf("blocklist:\n%s", buffer);

    /* Send blocklist buffer to kernel */
    if (!blocklist_send(buffer))
        exit(1);

    return 0;
}
