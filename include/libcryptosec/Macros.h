#ifndef INCLUDE_LIBCRYPTOSEC_MACROS_H_
#define INCLUDE_LIBCRYPTOSEC_MACROS_H_

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT_FILE __FILE__ ":" TOSTRING(__LINE__)

#define AT_FUNCTION __PRETTY_FUNCTION__

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
