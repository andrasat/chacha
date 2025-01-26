#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "ecrypt-sync.h"

// Function to get current time in microseconds
double get_time_usec()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1e6 + tv.tv_usec;
}

// Function to run benchmark with different message sizes
void run_benchmark(size_t message_size, int iterations)
{
  ECRYPT_ctx ctx;

  // Prepare key and IV
  u8 key[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  u8 iv[8] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  // Allocate message and ciphertext buffers
  u8 *message = (u8 *)malloc(message_size);
  u8 *ciphertext = (u8 *)malloc(message_size);

  if (!message || !ciphertext)
  {
    printf("Memory allocation failed!\n");
    return;
  }

  // Fill message with random data
  for (size_t i = 0; i < message_size; i++)
  {
    message[i] = rand() & 0xFF;
  }

  // Initialize cipher
  ECRYPT_init();
  ECRYPT_keysetup(&ctx, key, 256, 64);

  // Timing variables
  double total_time = 0;
  double start_time, end_time;

  // Run benchmark
  for (int i = 0; i < iterations; i++)
  {
    ECRYPT_ivsetup(&ctx, iv);

    start_time = get_time_usec();
    ECRYPT_encrypt_bytes(&ctx, message, ciphertext, message_size);
    end_time = get_time_usec();

    total_time += (end_time - start_time);
  }

  // Calculate and print results
  double avg_time = total_time / iterations;
  double throughput = (message_size * iterations) / (total_time / 1e6); // bytes per second
  double throughput_mbps = throughput / (1024 * 1024);                  // MB/s

  printf("Message size: %zu bytes\n", message_size);
  printf("Iterations: %d\n", iterations);
  printf("Average time: %.2f microseconds\n", avg_time);
  printf("Throughput: %.2f MB/s\n", throughput_mbps);
  printf("--------------------\n");

  // Clean up
  free(message);
  free(ciphertext);
}

int main()
{
  // Seed random number generator
  srand(time(NULL));

  // Test different message sizes
  size_t sizes[] = {
      64,              // 64 bytes
      1024,            // 1 KB
      1024 * 1024,     // 1 MB
      10 * 1024 * 1024 // 10 MB
  };

  // Number of iterations for each size
  int iterations[] = {
      10000, // More iterations for small sizes
      1000,
      1000,
      1000 // Fewer iterations for large sizes
  };

  printf("ChaCha Cipher Performance Benchmark\n");
  printf("==================================\n");

  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
  {
    run_benchmark(sizes[i], iterations[i]);
  }

  return 0;
}