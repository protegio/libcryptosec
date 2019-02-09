#include <libcryptosec/certificate/CertificateRequestFactory.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>

#include <string.h>

CertificateRequestSPKAC CertificateRequestFactory::fromSPKAC(const std::string& path)
{
	NETSCAPE_SPKI *spki = NULL;
	EVP_PKEY *pktmp = NULL;
	char *buf = NULL;
	long errline;
	int rc;

	/*
	 * Load input file into a hash table.  (This is just an easy
	 * way to read and parse the file, then put it into a convenient
	 * STACK format).
	 */
	LHASH_OF(CONF_VALUE) *parms = CONF_load(NULL, path.c_str(), &errline);
	THROW_DECODE_ERROR_IF(parms == NULL);

	STACK_OF(CONF_VALUE) *sk = CONF_get_section(parms, "default");
	THROW_DECODE_ERROR_AND_FREE_IF(sk == NULL || sk_CONF_VALUE_num(sk) == 0,
			// TODO: esse free está correto?
			CONF_free(parms);
	);

	/*
	 * Now create a dummy X509 request structure.  We don't actually
	 * have an X509 request, but we have many of the components
	 * (a public key, various DN components).  The idea is that we
	 * put these components into the right X509 request structure
	 * and we can use the same code as if you had a real X509 request.
	 */
	X509_REQ *req = X509_REQ_new();
	THROW_DECODE_ERROR_AND_FREE_IF(req == NULL,
			// TODO: esse free está correto?
			CONF_free(parms);
	);

	/*
	 * Build up the subject name set.
	 */
	const X509_NAME *constName = X509_REQ_get_subject_name(req);
	X509_NAME *name = X509_NAME_dup((X509_NAME*) constName);

	THROW_DECODE_ERROR_AND_FREE_IF(name == NULL,
			X509_REQ_free(req);
			CONF_free(parms);
			X509_NAME_free(name);
	);

	for (int i = 0; ; i++) {
		if (sk_CONF_VALUE_num(sk) <= i) {
			break;
		}

		CONF_VALUE *cv = sk_CONF_VALUE_value(sk, i);
		THROW_DECODE_ERROR_AND_FREE_IF(cv == NULL,
				X509_REQ_free(req);
				CONF_free(parms);
				X509_NAME_free(name);
		);

		char *type = cv->name;

		/* Skip past any leading X. X: X, etc to allow for
		 * multiple instances
		 */
		for (buf = cv->name; *buf ; buf++) {
			if ((*buf == ':') || (*buf == ',') || (*buf == '.')) {
				buf++;
				if (*buf) {
					type = buf;
				}
				break;
			}
		}

		buf = cv->value;
		int nid = OBJ_txt2nid(type);
		if (nid == NID_undef) {
			if (strcmp(type, "SPKAC") == 0) {
				spki = NETSCAPE_SPKI_b64_decode(cv->value, -1);
				THROW_DECODE_ERROR_AND_FREE_IF(spki == NULL,
						X509_REQ_free(req);
						CONF_free(parms);
						X509_NAME_free(name);
				);
			}
			continue;
		}

		// TODO: check MBSTRING_ASC
		rc = X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC, (unsigned char *)buf, -1, -1, 0);
		THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
				X509_REQ_free(req);
				CONF_free(parms);
				X509_NAME_free(name);
				NETSCAPE_SPKI_free(spki);
		);
	}

	THROW_DECODE_ERROR_AND_FREE_IF(spki == NULL,
			X509_REQ_free(req);
			CONF_free(parms);
			X509_NAME_free(name);
	);

	/*
	 * Now extract the key from the SPKI structure.
	 */
	pktmp = NETSCAPE_SPKI_get_pubkey(spki); // TODO: retorna cópia ou referência?
	THROW_DECODE_ERROR_AND_FREE_IF(pktmp == NULL,
			X509_REQ_free(req);
			CONF_free(parms);
			X509_NAME_free(name);
			NETSCAPE_SPKI_free(spki);
	);

	rc = X509_REQ_set_subject_name(req, name);
	X509_NAME_free(name);
	THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
			X509_REQ_free(req);
			CONF_free(parms);
			NETSCAPE_SPKI_free(spki);
			EVP_PKEY_free(pktmp);  // TODO: esse free é ok?
	);

	rc = X509_REQ_set_pubkey(req,pktmp);
	EVP_PKEY_free(pktmp);  // TODO: esse free é ok?
	THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
			X509_REQ_free(req);
			CONF_free(parms);
			NETSCAPE_SPKI_free(spki);
	);

	CertificateRequestSPKAC ret(req, spki);

	X509_REQ_free(req);
	CONF_free(parms);
	NETSCAPE_SPKI_free(spki);

	return ret;
}
