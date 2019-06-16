#ifndef BYTEARRAY_H_
#define BYTEARRAY_H_

#include <openssl/asn1.h>

#include <sstream>
#include <string>

/**
 * @ingroup Util
 */

/**
 * @brief Classe usada para transportar dados binários pelo sistema. Pode ser usada para conversão de 
 * texto em array de bytes e vice-versa. Usar esta classe ao invés do QByteArray por causa do uso de
 * "unsigned char", e pela possibilidade de fazer "cópias profundas" dos dados.
 */
class ByteArray
{

public:

	/**
	 * @brief Constrói um ByteArray vazio de tamanho 0.
	 */
    ByteArray();

	/**
	 * @brief Constrói um ByteArray de tamanho definido igual a \p size.
	 * 
	 * @param size tamanho do novo ByteArray.
	 */
	ByteArray(uint32_t size);

	/**
	 * @brief Constrói um ByteArray a partir do buffer desejado, copiando os dados.
	 * 
	 * @param data		Array de bytes a ser copiado.
	 * @param size	Tamanho do array de bytes.
	 */
    ByteArray(const uint8_t* data, uint32_t size);

	/**
	 * @brief Constrói um ByteArray a partir de uma std::string.
	 * 
	 * @param str	A std::string que será copiada para o ByteArray.
	 */
    ByteArray(const std::string& str);

	/**
	 * @brief Constrói um ByteArray a partir de outro ByteArray.
	 * 
	 * O conteúdo do ByteArray é copiado.
	 *
	 * @param value	O ByteArray de origem.
	 */
    ByteArray(const ByteArray& value);

	/**
	 * @brief Constrói um ByteArray a partir de outro ByteArray.
	 *
	 * O conteúdo do ByteArray é movido.
	 *
	 * @param value	O ByteArray de origem.
	 */
    ByteArray(ByteArray&& value);

	/**
	 * @brief Destrutor.
	 */
	virtual ~ByteArray();

    /**
     * @brief Faz uma cópia do ByteArray passado.
     *
     * @param value	O ByteArray a ser copiado.
     *
     * @return O ByteArray resultante da cópia.
     */
    ByteArray& operator=(const ByteArray& value);


    /**
     * @brief Move o conteúdo de um ByteArray para outro.
     *
     * @param value	O ByteArray a ser movido.
     *
     * @return O novo ByteArray.
     */
    ByteArray& operator=(ByteArray&& value);

    /**
     * @brief Lê o byte da posição desejada.
     * 
     * @param pos	A posição desejada.
     *
     * @return O valor do byte na posição passada.
     * @throw std::out_of_bound Se a posição ultrapassar o tamanho do ByteArray.
     */
    uint8_t& at(uint32_t pos) const;
    
    /**
     * @brief Lê ou escreve o byte da posição desejada.
     *
     * @param pos	A posição desejada.
     *
     * @return A referência para o byte da posição.
     * @throw std::out_of_bound Se a posição ultrapassar o tamanho do ByteArray.
     */
    uint8_t& operator [](uint32_t pos);

    /**
     * @brief Compara dois ByteArray e retorna true se forem iguais, false caso contrário.
     * 
     * @param left	Primeiro ByteArray da comparação.
     * @param right	Segundo ByteArray da comparação.
     *
     * @return True se forem iguais, false caso contrário.
     */
    friend bool operator ==(const ByteArray& left, const ByteArray& right);
    
    /**
     * @brief Compara dois ByteArray e retorna true se forem diferentes, false caso contrário.
     * 
     * @param left	Primeiro ByteArray da comparação.
     * @param right	Segundo ByteArray da comparação.
     *
     * @return True se forem diferentes, false caso contrário.
     */
    friend bool operator !=(const ByteArray& left, const ByteArray& right);

    /**
     * @brief Executa a operação lógica xor entre dois ByteArray.
     * 
     * Essa função constrói um novo ByteArray com o resultado da operação.
     *
     * Se os ByteArray tiverem tamanhos diferentes, o ByteArray de menor tamanho
     * é expandido com zeros até ficar do tamanho do maior ByteArray.
     *
     * @param left	Primeiro ByteArray da operação.
     * @param right	Segundo ByteArray da operação.
     *
     * @return O ByteArray resultante da operação xor.
     */
    friend ByteArray& operator xor(const ByteArray& left, const ByteArray& right);

    /**
     * @brief Copia os dados do ByteArray \p from.
     *
     * O tamanho do ByteArray de destino (\p this) será expandido se necessário.
     *
     * @param from			ByteArray a ser copiado.
     * @param fromOffset	Offset da origem.
     * @param toOffset		Offset de destino.
     * @param numberOfBytes	Número de bytes a serem copiados.
     *
     * @throw std::overflow_error se o tamanho total da origem ou destino ultrapassar UINT32_MAX.
     * @throw std::out_of_range se a combinaão de offset e número de bytes ultrapassar o tamanho da origem.
     */
    void copy(const ByteArray& from, uint32_t fromOffset, uint32_t toOffset, uint32_t numberOfBytes);

    /**
     * @return Um ponteiro const para o array de bytes gerenciado pelo ByteArray.
     */
    const uint8_t* getConstDataPointer() const;

    /**
     * @return Um ponteiro para o array de bytes gerenciado pelo ByteArray.
     */
    uint8_t* getDataPointer();

    /**
     * @return O tamanho do ByteArray.
     */
    unsigned int getSize() const;
    
    /**
     * @brief Define o tamanho do ByteArray.
     *
     * @param size	O tamanho desejado para o ByteArray.
     */
    void setSize(unsigned int size);

    /**
     * @brief Retorna o ByteArray como uma std::string.
     *
     * @return A std::string.
     */
    virtual std::string toString() const;
    
    /**
     * @return A representação hexadecimal do ByteArray.
     */    
    virtual std::string toHex() const;
    
    /**
     * @param separator O separador a ser usado a cada dois caracteres hexadecimal.
     * @return A representação hexadecimal do ByteArray.
     */
    virtual std::string toHex(char separator) const;
    
    /**
     * @return A representação ASN1_OCTET_STRING do ByteArray.
     * TODO: getAsn1.. o toAsn1..?
     */
    ASN1_OCTET_STRING* getAsn1OctetString() const;

    /**
     * @brief Sobrescreve os dados do ByteArray.
     *
     * @param useRandomBytes Indica que o ByteArray deve ser sobrescrito com dados
     * aleatórios, caso contrário ele será sobrescrito com zeros.O RNG utilizado
     * é o RAND_bytes do OpenSSL.
     */
    virtual void burn(bool useRandomBytes = false);

private:
    unsigned int size;
    unsigned int originalSize;
    unsigned char* m_data;
};

#endif /*BYTEARRAY_H_*/
