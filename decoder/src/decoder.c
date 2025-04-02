/*
 * @author: Jacob Wyrozebski
 *
 * Secure Decoder for MAX78000FTHR - eCTF 2025
 *
 * - Ensures secure decryption with AES-256-GCM
 * - Enforces monotonic timestamps to prevent replay attacks
 * - Validates channel subscriptions based on `secrets.json`
 * - Uses HMAC-SHA256 authentication for message integrity
*/

#include "mxc_device.h"
#include "board.h"
#include "uart.h"
#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
 
#define UART_BAUD          115200
#define MAX_FRAME_SIZE     64
#define HEADER_SIZE        12  // 4 bytes (channel) + 8 bytes (timestamp)
#define NONCE_SIZE         12
#define TAG_SIZE           16
#define HMAC_SIZE          32
#define NUM_SUBSCRIPTIONS  5  // Define max number of subscriptions
 
// Secure AES-256 Encryption Key (Stored in Secure Flash)
static const uint8_t aes_key[32] __attribute__((section(".flash_sec"))) =
{
    0xA1, 0xF3, 0xD5, 0xB9, 0x7E, 0x8C, 0x12, 0x34,
    0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34,
    0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34,
    0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34
};
 
// Secure HMAC-SHA256 Authentication Key (Stored in Secure Flash)
static const uint8_t hmac_key[32] __attribute__((section(".flash_sec"))) =
{
    0xB9, 0xBA, 0xDC, 0x2A, 0x99, 0xF2, 0x89, 0xC3,
    0x40, 0xB5, 0xF3, 0x4F, 0xED, 0x3D, 0x10, 0xE5,
    0x1F, 0x3C, 0x01, 0x75, 0x75, 0x6E, 0xB0, 0xAF,
    0x3D, 0x3A, 0x2F, 0x80, 0x81, 0xC4, 0xC9, 0x78
};
 
// Allowed Channels (Hardcoded to match `secrets.json`)
static const uint32_t allowed_channels[] __attribute__((section(".flash_sec"))) = {1, 3, 4};
 
// Subscription structure
typedef struct
{
    uint32_t channel;
    uint64_t start_time;
    uint64_t end_time;
} Subscription;
 
static Subscription subscription_table[NUM_SUBSCRIPTIONS] __attribute__((section(".flash_sec")));
 
// Validate Subscription Against Allowed Channels
static int is_channel_allowed(uint32_t channel)
{
    for (size_t i = 0; i < sizeof(allowed_channels) / sizeof(allowed_channels[0]); i++)
    {
        if (allowed_channels[i] == channel)
        {
            return 1;  // Valid channel
        }
    }
    return 0;  // Invalid channel
}
 
// Monotonic Timestamp Enforcement
static uint64_t last_timestamp __attribute__((section(".flash_sec"))) = 0;
 
// UART output function
static mxc_uart_regs_t *ConsoleUart = MXC_UART_GET_UART(CONSOLE_UART);

static void uart_printf(const char *fmt, ...)
{
    char buffer[128];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    MXC_UART_Write(ConsoleUart, (uint8_t *)buffer, strlen(buffer));
}
 
// Validate subscription for channel & timestamp
static int subscription_is_valid(uint32_t channel, uint64_t timestamp)
{
    for (size_t i = 0; i < NUM_SUBSCRIPTIONS; i++)
    {
        if (subscription_table[i].channel == channel && timestamp >= subscription_table[i].start_time && timestamp <= subscription_table[i].end_time)
        {
            return 1;
        }
    }

    return 0;
 }
 
int main(void)
{
    SystemInit();
    MXC_UART_Init(ConsoleUart, UART_BAUD);
    uart_printf("MAX78000 Secure Decoder Initialized\n");

    uint8_t encoded_buf[136] = {0}; // Buffer for encrypted data
 
    // Extract channel & timestamp
    uint32_t channel;
    uint64_t timestamp;
    memcpy(&channel, encoded_buf, 4);
    memcpy(&timestamp, encoded_buf + 4, 8);
 
    // Enforce strictly increasing timestamps
    if (timestamp <= last_timestamp)
    {
        uart_printf("Error: Non-monotonic timestamp.\n");
        return -1;
    }

    last_timestamp = timestamp;
 
    // Check if channel is subscribed
    if (!subscription_is_valid(channel, timestamp))
    {
        uart_printf("Error: Invalid subscription for channel=%u\n", channel);
        return -1;
    }
 
    // Extract cryptographic components
    uint8_t *nonce = encoded_buf + HEADER_SIZE;
    uint8_t *ciphertext = encoded_buf + HEADER_SIZE + NONCE_SIZE;
    uint8_t *hmac_received = encoded_buf + HEADER_SIZE + NONCE_SIZE + MAX_FRAME_SIZE + TAG_SIZE;
 
    // Verify HMAC authentication
    uint8_t hmac_calc[HMAC_SIZE];
    sc_hmac_sha256(encoded_buf, HEADER_SIZE + NONCE_SIZE + MAX_FRAME_SIZE + TAG_SIZE, hmac_key, hmac_calc);

    if (memcmp(hmac_received, hmac_calc, HMAC_SIZE) != 0)
    {
        uart_printf("Error: HMAC verification failed.\n");
        return -1;
    }

    uart_printf("Frame HMAC verified.\n");
 
    // Decrypt frame data
    uint8_t plaintext[MAX_FRAME_SIZE + 1] = {0};
    if (sc_aes_gcm_decrypt(ciphertext, MAX_FRAME_SIZE, aes_key, nonce, encoded_buf, HEADER_SIZE, hmac_received, plaintext) != 0)
    {
        uart_printf("Error: AES-GCM decryption failed.\n");
        return -1;
    }

    plaintext[MAX_FRAME_SIZE] = '\0';
 
    // Print decoded frame
    uart_printf("Channel: %u\n", channel);
    uart_printf("Timestamp: %llu\n", (unsigned long long)timestamp);
    uart_printf("Decoded Frame: %s\n", plaintext);
 
    // Securely erase sensitive data from memory
    memset(plaintext, 0, sizeof(plaintext));
    memset(encoded_buf, 0, sizeof(encoded_buf));
    memset(hmac_calc, 0, sizeof(hmac_calc));
 
    return 0;
}
 