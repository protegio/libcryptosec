#ifndef INCLUDE_LIBCRYPTOSEC_MACROS_H_
#define INCLUDE_LIBCRYPTOSEC_MACROS_H_

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT_FILE __FILE__ ":" TOSTRING(__LINE__)

#define AT_FUNCTION __PRETTY_FUNCTION__

#define THROW(exception, reason) throw exception(reason, AT_FUNCTION)
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

#define THROW_ENCODE_ERROR_IF(exp) THROW_IF(exp, CertificationException, CertificationException::ENCODE_ERROR)
#define THROW_ENCODE_ERROR_AND_FREE_IF(exp, free_code) THROW_AND_FREE_IF(exp, CertificationException, CertificationException::ENCODE_ERROR, free_code)
#define THROW_DECODE_ERROR_IF(exp) THROW_IF(exp, CertificationException, CertificationException::DECODE_ERROR)
#define THROW_DECODE_ERROR_AND_FREE_IF(exp, free_code) THROW_AND_FREE_IF(exp, CertificationException, CertificationException::DECODE_ERROR, free_code)

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
