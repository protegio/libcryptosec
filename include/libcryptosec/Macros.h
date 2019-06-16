#ifndef INCLUDE_LIBCRYPTOSEC_MACROS_H_
#define INCLUDE_LIBCRYPTOSEC_MACROS_H_

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT_FILE __FILE__ ":" TOSTRING(__LINE__)

#define AT_FUNCTION __PRETTY_FUNCTION__

#define THROW(exception, reason) throw exception(reason, AT_FUNCTION)

#define THROW_NO_REASON(exception) throw exception(AT_FUNCTION)

#define THROW_IF(exp, exception, reason)\
do {\
	if ((exp)) {\
		THROW(exception, reason);\
	}\
} while(false)

#define THROW_AND_FREE_IF(exp, exception, reason, free_code)\
do {\
	if ((exp)) {\
		free_code\
		THROW(exception, reason);\
	}\
} while(false)

#define THROW_NO_REASON_IF(exp, exception)\
do {\
	if ((exp)) {\
		THROW_NO_REASON(exception);\
	}\
} while(false)

#define THROW_NO_REASON_AND_FREE_IF(exp, exception, free_code)\
do {\
	if ((exp)) {\
		free_code\
		THROW_NO_REASON(exception);\
	}\
} while(false)

#define THROW_ENCODE_ERROR_IF(exp) THROW_NO_REASON_IF(exp, EncodeException)
#define THROW_ENCODE_ERROR_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, EncodeException, free_code)

#define THROW_DECODE_ERROR_IF(exp) THROW_NO_REASON_IF(exp, DecodeException)
#define THROW_DECODE_ERROR_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, DecodeException, free_code)

#define THROW_OPERATION_ERROR_IF(exp) THROW_NO_REASON_IF(exp, OperationException)
#define THROW_OPERATION_ERROR_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, OperationException, free_code)

#define THROW_BAD_ALLOC_IF(exp) THROW_NO_REASON_IF(exp, DecodeException)
#define THROW_BAD_ALLOC_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, DecodeException, free_code)

#define THROW_DIVISION_BY_ZERO_IF(exp) THROW_NO_REASON_IF(exp, DecodeException)
#define THROW_DIVISION_BY_ZERO_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, DecodeException, free_code)

#define THROW_OPERATION_IF(exp) THROW_NO_REASON_IF(exp, DecodeException)
#define THROW_OPERATION_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, DecodeException, free_code)

#define THROW_OVERFLOW_IF(exp) THROW_NO_REASON_IF(exp, std::overflow_error)
#define THROW_OVERFLOW_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, std::overflow_error, free_code)

#define THROW_OUT_OF_RANGE_IF(exp) THROW_NO_REASON_IF(exp, std::out_of_range)
#define THROW_OUT_OF_RANGE_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, std::out_of_range, free_code)


#define THROW_NULL_POINTER_IF(exp) THROW_NO_REASON_IF(exp, NullPointerException)
#define THROW_NULL_POINTER_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, NullPointerException, free_code)

#define THROW_ENCODE_IF(exp) THROW_NO_REASON_IF(exp, EncodeException)
#define THROW_ENCODE_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, EncodeException, free_code)

#define THROW_DECODE_IF(exp) THROW_NO_REASON_IF(exp, DecodeException)
#define THROW_DECODE_AND_FREE_IF(exp, free_code) THROW_NO_REASON_AND_FREE_IF(exp, DecodeException, free_code)

#define DECODE_PEM(dst, str, decode_foo)\
	do {\
	BIO *buffer = BIO_new(BIO_s_mem());\
	THROW_DECODE_ERROR_IF(buffer == NULL);\
	unsigned int numberOfBytes = BIO_write(buffer, str.c_str(), str.size());\
	/* CAST: we need to check the integer limit because of the implicit cast above */\
	THROW_DECODE_ERROR_AND_FREE_IF(numberOfBytes >= INT32_MAX || numberOfBytes != str.size(),\
			BIO_free(buffer);\
	);\
	dst = decode_foo(buffer, NULL, NULL, NULL);\
	BIO_free(buffer);\
	THROW_DECODE_ERROR_IF(dst == NULL);\
	} while(false)

#define DECODE_DER(dst, byte_array, decode_foo)\
	do {\
	BIO *buffer = BIO_new(BIO_s_mem());\
	THROW_DECODE_ERROR_IF(buffer == NULL);\
	unsigned int numberOfBytes = BIO_write(buffer, byte_array.getConstDataPointer(), byte_array.getSize());\
	/* CAST: we need to check the integer limit because of the implicit cast above */\
	THROW_DECODE_ERROR_AND_FREE_IF(numberOfBytes >= INT32_MAX || numberOfBytes != byte_array.getSize(),\
			BIO_free(buffer);\
	);\
	/* TODO: will the second parameter work fine ? */\
	dst = decode_foo(buffer, NULL);\
	BIO_free(buffer);\
	THROW_DECODE_ERROR_IF(dst == NULL);\
	} while(false)

#define _ENCODE(src, encode_foo)\
	unsigned char *data;\
	BIO *buffer = BIO_new(BIO_s_mem());\
	THROW_ENCODE_ERROR_IF(buffer == NULL);\
	\
	int wrote = encode_foo(buffer, src);\
	THROW_ENCODE_ERROR_AND_FREE_IF(wrote <= 0,\
			BIO_free(buffer);\
	);\
	\
	int ndata = BIO_get_mem_data(buffer, &data);\
	THROW_ENCODE_ERROR_AND_FREE_IF(ndata <= 0,\
		BIO_free(buffer);\
	);\
	\
	ByteArray ret(data, ndata);\
	BIO_free(buffer)\

#define ENCODE_PEM_AND_RETURN(src, encode_foo)\
	do { \
	_ENCODE(src, encode_foo);\
	return ret.toString(); \
	} while(false)

#define ENCODE_DER_AND_RETURN(src, encode_foo)\
	do { \
	_ENCODE(src, encode_foo);\
	return ret; \
	} while(false)

#define ENCODE_ENCRYPTED_PEM_AND_RETURN(src, encode_foo, cipher, callback, passphrase)\
	do {\
	unsigned char *data;\
	BIO *buffer = BIO_new(BIO_s_mem());\
	THROW_ENCODE_ERROR_IF(buffer == NULL);\
	\
	int wrote = encode_foo(buffer, src, cipher, NULL, 0, callback, passphrase);\
	THROW_ENCODE_ERROR_AND_FREE_IF(wrote <= 0,\
			BIO_free(buffer);\
	);\
	\
	int ndata = BIO_get_mem_data(buffer, &data);\
	THROW_ENCODE_ERROR_AND_FREE_IF(ndata <= 0,\
		BIO_free(buffer);\
	);\
	\
	ByteArray ret(data, ndata);\
	BIO_free(buffer);\
	return ret.toString();\
	} while(false)

#define DECLARE_ENUM(name, size, ...) \
	enum name { \
	__VA_ARGS__ \
	}; \
\
	static const name name##List[size];

#define INITIALIZE_ENUM(name, size, ...) \
	const name name##List[size] = { \
	__VA_ARGS__ \
	}

#endif /* INCLUDE_LIBCRYPTOSEC_MACROS_H_ */
