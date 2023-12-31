/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/sys/printk.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/kernel.h>  // Include this header for k_uptime_get()

#define MAX_DEVICES 10  // Maximum number of unique devices to track
#define NAME_LEN 30
#define INACTIVITY_TIMEOUT_MS (15 * 1000)  // 15s in milliseconds

struct active_device {
    bt_addr_le_t addr;
    uint32_t last_seen;
};

static struct active_device active_devices[MAX_DEVICES];  // Array to store active devices
static int num_active_devices = 0;  // Counter for the number of active devices

// Check if a device address is already tracked as active
static struct active_device *find_active_device(const bt_addr_le_t *addr)
{
    for (int i = 0; i < num_active_devices; i++) {
        if (bt_addr_le_cmp(addr, &active_devices[i].addr) == 0) {
            return &active_devices[i];
        }
    }
    return NULL;
}

// Add a device address to the list of active devices or update the timestamp
static void update_active_device(const bt_addr_le_t *addr, const char *addr_str)
{
    struct active_device *device = find_active_device(addr);
    uint32_t timestamp = k_uptime_get_32();  // Get uptime in milliseconds

    if (device) {
        device->last_seen = timestamp;
    } else if (num_active_devices < MAX_DEVICES) {
        active_devices[num_active_devices].addr = *addr;
        active_devices[num_active_devices].last_seen = timestamp;

        // Format the timestamp as hh:mm:ss
        uint32_t seconds = timestamp / 1000;
        uint32_t minutes = seconds / 60;
        uint32_t hours = minutes / 60;

        seconds %= 60;
        minutes %= 60;

        // Format the timestamp as hh:mm:ss
        char timestamp_str[9];  // "hh:mm:ss\0"
        snprintf(timestamp_str, sizeof(timestamp_str), "%02u:%02u:%02u", hours, minutes, seconds);

        printk("New active device detected: %s, Timestamp: %s, Current active devices: %d\n", addr_str, timestamp_str,num_active_devices + 1);
        num_active_devices++;
    }
}

// Remove inactive devices based on inactivity timeout
static void remove_inactive_devices(const char *addr_str)
{
    uint32_t current_time = k_uptime_get_32();

    for (int i = 0; i < num_active_devices; ) {
        if (current_time - active_devices[i].last_seen > INACTIVITY_TIMEOUT_MS) {
            // Format the timestamp as hh:mm:ss
            uint32_t seconds = active_devices[i].last_seen / 1000;
            uint32_t minutes = seconds / 60;
            uint32_t hours = minutes / 60;

            seconds %= 60;
            minutes %= 60;

            // Format the timestamp as hh:mm:ss
            char timestamp_str[9];  // "hh:mm:ss\0"
            snprintf(timestamp_str, sizeof(timestamp_str), "%02u:%02u:%02u", hours, minutes, seconds);

            printk("Inactive device removed: %s, Last Seen: %s, Current active devices: %d\n", addr_str, timestamp_str,num_active_devices - 1 );
            num_active_devices--;

            // Remove inactive device by shifting remaining devices
            for (int j = i; j < num_active_devices; j++) {
                active_devices[j] = active_devices[j + 1];
            }
        } else {
            i++;
        }
    }
}

/*bl addr types: BT_GAP_ADV_TYPE_ 	0 means Scannable and connectable advertising.
										1 means Directed connectable advertising.
										2 means Non-connectable and scannable advertising.
										3 means Non-connectable and non-scannable advertising.
										4 means Additional advertising data requested by an active scanner.
										5 means Extended advertising, see advertising properties.
	*/
static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
                         struct net_buf_simple *ad)
{
    char addr_str[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

    update_active_device(addr, addr_str);
	
	
	//printk("Device found: %s (RSSI %d), type %u, AD data len %u\n",addr_str, rssi, type, ad->len);

    remove_inactive_devices(addr_str);
	
	
	/*if (!is_device_scanned(addr)) {
        add_scanned_device(addr);
        printk("New device found: %s (RSSI %d), type %u, AD data len %u, Timestamp: %s  \n",
               addr_str, rssi, type, ad->len, timestamp_str);
    } else {
        printk("Duplicate device found: %s (RSSI %d), type %u, AD data len %u\n", addr_str, rssi, type, ad->len);
    }
	*/
}

#if defined(CONFIG_BT_EXT_ADV)
static bool data_cb(struct bt_data *data, void *user_data)
{
	char *name = user_data;
	uint8_t len;

	switch (data->type) {
	case BT_DATA_NAME_SHORTENED:
	case BT_DATA_NAME_COMPLETE:
		len = MIN(data->data_len, NAME_LEN - 1);
		(void)memcpy(name, data->data, len);
		name[len] = '\0';
		return false;
	default:
		return true;
	}
}

static const char *phy2str(uint8_t phy)
{
	switch (phy) {
	case BT_GAP_LE_PHY_NONE: return "No packets";
	case BT_GAP_LE_PHY_1M: return "LE 1M";
	case BT_GAP_LE_PHY_2M: return "LE 2M";
	case BT_GAP_LE_PHY_CODED: return "LE Coded";
	default: return "Unknown";
	}
}

static void scan_recv(const struct bt_le_scan_recv_info *info,
		      struct net_buf_simple *buf)
{
	char le_addr[BT_ADDR_LE_STR_LEN];
	char name[NAME_LEN];
	uint8_t data_status;
	uint16_t data_len;

	(void)memset(name, 0, sizeof(name));

	data_len = buf->len;
	bt_data_parse(buf, data_cb, name);

	data_status = BT_HCI_LE_ADV_EVT_TYPE_DATA_STATUS(info->adv_props);

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
	if (false)//toggle manually for extra info
	 {
	printk("[DEVICE]: %s, AD evt type %u, Tx Pwr: %i, RSSI %i "
	       "Data status: %u, AD data len: %u Name: %s "
	       "C:%u S:%u D:%u SR:%u E:%u Pri PHY: %s, Sec PHY: %s, "
	       "Interval: 0x%04x (%u ms), SID: %u\n",
	       le_addr, info->adv_type, info->tx_power, info->rssi,
	       data_status, data_len, name,
	       (info->adv_props & BT_GAP_ADV_PROP_CONNECTABLE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_SCANNABLE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_DIRECTED) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_SCAN_RESPONSE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_EXT_ADV) != 0,
	       phy2str(info->primary_phy), phy2str(info->secondary_phy),
	       info->interval, info->interval * 5 / 4, info->sid);
	}
}

static struct bt_le_scan_cb scan_callbacks = {
	.recv = scan_recv,
};
#endif /* CONFIG_BT_EXT_ADV */

int observer_start(void)
{
	struct bt_le_scan_param scan_param = {
		.type       = BT_LE_SCAN_TYPE_PASSIVE,
		.options    = BT_LE_SCAN_OPT_FILTER_DUPLICATE,
		.interval   = BT_GAP_SCAN_FAST_INTERVAL,
		.window     = BT_GAP_SCAN_FAST_WINDOW,
	};
	int err;

#if defined(CONFIG_BT_EXT_ADV)
	bt_le_scan_cb_register(&scan_callbacks);
	printk("Registered scan callbacks\n");
#endif /* CONFIG_BT_EXT_ADV */

	err = bt_le_scan_start(&scan_param, device_found);
	if (err) {
		printk("Start scanning failed (err %d)\n", err);
		return err;
	}
	printk("Started scanning...\n");

	return 0;
	


}
