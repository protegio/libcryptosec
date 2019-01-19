#ifndef INCLUDE_LIBCRYPTOSEC_MACROS_H_
#define INCLUDE_LIBCRYPTOSEC_MACROS_H_


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
