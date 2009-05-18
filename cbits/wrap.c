#include <gcrypt.h>
#include <errno.h>
#include <pthread.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static int once = 0;

void hsgcrypt_wrap_gcrypt_init(void)
{
  if(0 == once++) {
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gcry_check_version(NULL);
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  }
}

