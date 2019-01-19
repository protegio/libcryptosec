#include <openssl/crypto.h>

/* we have this global to let the callback get easy access to it */
static pthread_rwlock_t *rwlocks;

void lock_callback(int mode, int type, char *file, int line) {
	(void) file;
	(void) line;
	if (mode & CRYPTO_LOCK) {
		pthread_rwlock_wrlock(&(rwlocks[type]));
	} else {
		pthread_rwlock_unlock(&(rwlocks[type]));
	}
}

unsigned long thread_id(void) {
	unsigned long ret;
	ret = (unsigned long) pthread_self();
	return (ret);
}

namespace libcryptosec {
void init() {
	// TODO: check return
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

	rwlocks = (pthread_rwlock_t *) OPENSSL_malloc(
			CRYPTO_num_locks() * sizeof(pthread_rwlock_t));
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_rwlock_init(&(rwlocks[i]), NULL);
	}

	CRYPTO_set_id_callback((unsigned long (*)())thread_id);CRYPTO_set_locking_callback
	((void (*)(int, int, const char*, int))lock_callback);
}

void finish() {
	CRYPTO_set_locking_callback (NULL);
	for (int i = 0; i < CRYPTO_num_locks(); i++)
		pthread_rwlock_destroy(&(rwlocks[i]));
	OPENSSL_free(rwlocks);
}
}

