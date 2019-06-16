#ifndef BASE64_H_
#define BASE64_H_

#include <string>

class ByteArray;

/**
 * @ingroup Util
 */

/**
 * @brief Classe de codificação em base 64.
 */

class Base64
{
public:

	/**
	 * @brief Codifica o dado passado para base 64.
	 *
	 * @data data O dado a ser codificado.
	 *
	 * @return O dado codificado em base64.
	 */
	static std::string encode(const ByteArray& data);

	/**
	 * @brief Decodifica o dado em base 64 para binário.
	 *
	 * @data data O dado a ser decodificado.
	 *
	 * @return O dado decodificado.
	 */
	static ByteArray decode(const std::string& data);

private:

	static const std::string base64Chars; //< Lista de caracteres da codificação em base 64.
};

#endif /*BASE64_H_*/
