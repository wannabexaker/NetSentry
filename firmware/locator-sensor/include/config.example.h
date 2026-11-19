// Copy this file to config.h (same folder) and fill it in.
// config.h is git-ignored: it holds your WiFi password.
#pragma once

// A short name for this sensor; it must match the `id` in NetSentry's config.
#define SENSOR_ID "s1"

// The 2.4 GHz network the sensor joins. Use the network your smart-home
// devices are on: the sensor hears whatever shares that access point's channel.
#define WIFI_SSID "your-network-name"
#define WIFI_PASSWORD "your-network-password"

// Optional shared key. If set, NetSentry must send the same value (`token` in
// the locator config). Leave "" to answer anyone on the network.
#define SENSOR_KEY ""

// Optional fixed address (recommended, so NetSentry always finds the sensor).
// Comma-separated, not dotted. Remove the three lines to use DHCP instead and
// reserve the address on your router.
// #define STATIC_IP      192, 0, 2, 61
// #define STATIC_GATEWAY 192, 0, 2, 1
// #define STATIC_MASK    255, 255, 255, 0
