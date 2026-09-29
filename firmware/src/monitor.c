// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/picokit-40-anti-replay
// File:    monitor.c
// Desc:    Implements the anti-replay state machine that tracks a per-node
//          sequence window and rejects a replayed frame.
// Created: 2026

#include "picokit_40_anti_replay.h"
#include "monitor.h"
#include "radio.h"
#include "status_led.h"
#include "ccm.h"
#include "envelope.h"
#include "field_secrets.h"
#include "hardware/gpio.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Module-ready flag.
 *
 * Set to true by monitor_init() once the peripherals are configured.
 * monitor_step() returns false while this flag is clear.
 */
static bool g_ready;

/**
 * @brief True when the most recent frame was rejected as a replay.
 */
static uint8_t g_replayed;

/**
 * @brief Monotonic transmit sequence number.
 */
static uint16_t g_seq;

/**
 * @brief Absolute time in microseconds of the next authenticated transmit.
 */
static uint64_t g_next_tx_us;

/**
 * @brief Inbound radio line accumulator.
 */
static char g_rx_line[RADIO_LINE_BUF_LEN];

/**
 * @brief Number of bytes currently held in the inbound line accumulator.
 */
static size_t g_rx_len;

/**
 * @brief AES-128 session key for telemetry.
 */
static uint8_t g_key[CCM_KEY_LEN];

/**
 * @brief True once the telemetry session key has been loaded.
 */
static bool g_key_ready;

/**
 * @brief Highest sequence number accepted by the replay window.
 */
static uint16_t g_replay_high;

/**
 * @brief Bitmap of the recent sequences just below the window high mark.
 */
static uint32_t g_replay_bits;

/**
 * @brief True once the replay window has accepted its first sequence.
 */
static bool g_replay_seen;

/**
 * @brief Configure the onboard heartbeat LED as a dark output.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init_io(void) {
    gpio_init(PICOKIT_40_ANTI_REPLAY_LED_PIN);
    gpio_set_dir(PICOKIT_40_ANTI_REPLAY_LED_PIN, GPIO_OUT);
    gpio_put(PICOKIT_40_ANTI_REPLAY_LED_PIN, 0);
}

/**
 * @brief Clear the replay window to its initial empty state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_replay_reset(void) {
    g_replay_seen = false;
    g_replay_high = 0u;
    g_replay_bits = 0u;
}

/**
 * @brief Reset the replay verdict, sequence, and transmit timing.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init(void) {
    uint64_t now_us = time_us_64();
    g_replayed = 0u;
    g_seq = 0u;
    monitor_replay_reset();
    g_next_tx_us = now_us + (uint64_t)PICOKIT_40_ANTI_REPLAY_TX_INTERVAL_MS * 1000u;
    g_ready = true;
}

/**
 * @brief Load the telemetry session key from the field secret.
 *
 * LAB-ONLY: production must provision the session key through OTP rather
 * than embedding a committed key.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_load_key(void) {
    static const uint8_t key[CCM_KEY_LEN] = FIELD_SECRET_KEY;
    memcpy(g_key, key, CCM_KEY_LEN);
    g_key_ready = true;
}

/**
 * @brief Print the boot banner for the anti-replay lesson.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_banner(void) {
    printf("=== PICOKIT-40 ANTI REPLAY // MONOTONIC SEQ + REPLAY WINDOW ===\n");
}

/**
 * @brief Derive the field key and announce a ready monitor.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_finish(void) {
    monitor_load_key();
    monitor_banner();
    return true;
}

/**
 * @brief Blink the onboard heartbeat LED exactly once.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_heartbeat(void) {
    gpio_put(PICOKIT_40_ANTI_REPLAY_LED_PIN, 1);
    sleep_us(MONITOR_HEARTBEAT_BLINK_US);
    gpio_put(PICOKIT_40_ANTI_REPLAY_LED_PIN, 0);
    sleep_us(MONITOR_HEARTBEAT_BLINK_US);
}

/**
 * @brief Seed an empty replay window with its first sequence.
 *
 * @param seq First sequence number accepted by the window.
 * @return bool true, because the first sequence is always accepted.
 */
static bool monitor_replay_seed(uint16_t seq) {
    g_replay_seen = true;
    g_replay_high = seq;
    g_replay_bits = 0u;
    return true;
}

/**
 * @brief Slide the window forward to a new higher sequence.
 *
 * @param seq New sequence number above the current window high mark.
 * @return void
 */
static void monitor_replay_advance(uint16_t seq) {
    uint16_t shift = (uint16_t)(seq - g_replay_high);
    if (shift >= MONITOR_REPLAY_WINDOW) {
        g_replay_bits = 0u;
    } else {
        g_replay_bits = (g_replay_bits << shift) | ((uint32_t)1u << shift);
    }
    g_replay_high = seq;
}

/**
 * @brief Mark one window bit, rejecting a sequence already marked.
 *
 * @param bit Window bit corresponding to the sequence.
 * @return bool true when the bit was newly set.
 */
static bool monitor_replay_set(uint32_t bit) {
    if ((g_replay_bits & bit) != 0u) {
        return false;
    }
    g_replay_bits |= bit;
    return true;
}

/**
 * @brief Mark a below-high sequence as seen within the window.
 *
 * @param seq Sequence number below the current window high mark.
 * @return bool true when the sequence is new, false when it is too old.
 */
static bool monitor_replay_mark(uint16_t seq) {
    uint16_t back = (uint16_t)(g_replay_high - seq);
    uint32_t bit;
    if (back >= MONITOR_REPLAY_WINDOW) {
        return false;
    }
    bit = (uint32_t)1u << back;
    return monitor_replay_set(bit);
}

/**
 * @brief Accept a sequence or reject it as a replay.
 *
 * @param seq Sequence number offered to the replay window.
 * @return bool true when the sequence is fresh, false when replayed.
 */
static bool monitor_replay_accept(uint16_t seq) {
    if (!g_replay_seen) {
        return monitor_replay_seed(seq);
    }
    if (seq == g_replay_high) {
        return false;
    }
    if (seq > g_replay_high) {
        monitor_replay_advance(seq);
        return true;
    }
    return monitor_replay_mark(seq);
}

/**
 * @brief Format the heartbeat JSON body for the replay verdict.
 *
 * @param frame Pointer to the mutable frame output buffer.
 * @param frame_len Capacity of the frame output buffer in bytes.
 * @return size_t Number of JSON bytes written, or zero on overflow.
 */
static size_t monitor_build_frame(char *frame, size_t frame_len) {
    int written = snprintf(frame, frame_len, "{\"n\":%u,\"s\":%u,\"r\":%u}", (unsigned)PACKET_NODE_ID, (unsigned)g_seq, (unsigned)g_replayed);
    return (written > 0 && (size_t)written < frame_len) ? (size_t)written : 0u;
}

/**
 * @brief Seal the current heartbeat body into a hex envelope.
 *
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the heartbeat was sealed and encoded.
 */
static bool monitor_seal_frame(char *hex, size_t hex_len) {
    char frame[PICOKIT_40_ANTI_REPLAY_FRAME_SIZE];
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    uint8_t ad = (uint8_t)PACKET_NODE_ID;
    size_t frame_len = monitor_build_frame(frame, sizeof(frame));
    envelope_fill_nonce(nonce);
    return envelope_seal_hex(g_key, nonce, &ad, 1u, (const uint8_t *)frame, frame_len, hex, hex_len);
}

/**
 * @brief Build and transmit the authenticated heartbeat frame.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_transmit(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!g_key_ready) {
        return;
    }
    monitor_replay_accept(g_seq);
    g_replayed = monitor_replay_accept(g_seq) ? 0u : 1u;
    if (monitor_seal_frame(hex, sizeof(hex))) {
        radio_send_frame(PICOKIT_40_ANTI_REPLAY_UART, (const uint8_t *)hex, strlen(hex));
        g_seq += 1u;
    }
}

/**
 * @brief Print one console line for the current heartbeat transmit.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_log_tx(void) {
    printf("SEQ %u replayed=%u\n", (unsigned)g_seq, (unsigned)g_replayed);
}

/**
 * @brief Transmit one heartbeat and schedule the next transmit.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_tx_tick(uint64_t now_us) {
    monitor_transmit();
    monitor_heartbeat();
    monitor_log_tx();
    g_next_tx_us = now_us + (uint64_t)PICOKIT_40_ANTI_REPLAY_TX_INTERVAL_MS * 1000u;
}

/**
 * @brief Drain inbound radio lines and log every valid +RCV report.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_rx_tick(void) {
    radio_rcv_t rcv;
    while (radio_line_pump(PICOKIT_40_ANTI_REPLAY_UART, g_rx_line, &g_rx_len)) {
        if (radio_parse_rcv(g_rx_line, &rcv) == RADIO_RESULT_OK) {
            printf("RX from 0x%04X, %u bytes\n", (unsigned)rcv.sender, (unsigned)rcv.len);
        }
    }
}

/**
 * @brief Service the heartbeat transmit timer.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_service_timers(uint64_t now_us) {
    if (now_us >= g_next_tx_us) {
        monitor_tx_tick(now_us);
    }
}

bool monitor_init(void) {
    bool ok;
    ok = status_led_init() && radio_init(PICOKIT_40_ANTI_REPLAY_UART);
    monitor_state_init_io();
    monitor_state_init();
    return ok && monitor_finish();
}

void monitor_deinit(void) {
    g_ready = false;
}

bool monitor_step(void) {
    uint64_t now_us;
    if (!g_ready) {
        return false;
    }
    now_us = time_us_64();
    monitor_service_timers(now_us);
    monitor_rx_tick();
    return true;
}
