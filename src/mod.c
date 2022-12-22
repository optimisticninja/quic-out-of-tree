#include <linux/module.h>

#include "streams/frame.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Holly <j@optimistic.ninja>");

static int __init quic_init(void) {
  printk(KERN_DEBUG "[QUIC]: Loaded...\n");

  // TODO: Remove testing and write a suite/fuzzer
  test_vli();
  return 0;
}

static void __exit quic_exit(void) { printk(KERN_DEBUG "QUIC: Unloaded...\n"); }

module_init(quic_init);
module_exit(quic_exit);
