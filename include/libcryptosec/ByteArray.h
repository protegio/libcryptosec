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
	ByteArray(unsigned int size);

	/**
	 * @brief Constrói um ByteArray a partir do buffer desejado, copiando os dados.
	 * 
	 * @param data		Array de bytes a ser copiado.
	 * @param size	Tamanho do array de bytes.
	 */
    ByteArray(const unsigned char* data, unsigned int size);

	/**
	 * @brief Constrói um ByteArray a partir de um std::ostringstream, copiando os dados.
	 * 
	 * @param buffer string stream com os dados a serem copiados.
	 */
    ByteArray(std::ostringstream *buffer);

	/**
	 * @brief Constrói um ByteArray a partir de uma std::string.
	 * 
	 * A string precisa terminar em \0, que também é copiado para o ByteArray.
	 *
	 * @param str	A std::string que será copiada para o ByteArray.
	 */
    ByteArray(const std::string& str);

	/**
	 * @brief Constrói um ByteArray a partir de uma std::string.
	 *
	 * A string precisa terminar em \0, que também é copiado para o ByteArray.
	 *
	 * @param str	A string que será copiada para o ByteArray.
	 */
	ByteArray(const char *str);

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
    unsigned char at(unsigned int pos) const;
    
    /**
     * @brief Lê ou escreve o byte da posição desejada.
     *
     * @param pos	A posição desejada.
     *
     * @return A referência para o byte da posição.
     * @throw std::out_of_bound Se a posição ultrapassar o tamanho do ByteArray.
     */
    unsigned char& operator[](unsigned int pos);

    /**
     * @brief Compara dois ByteArray e retorna true se forem iguais, false caso contrário.
     * 
     * @param left	Primeiro ByteArray da comparação.
     * @param right	Segundo ByteArray da comparação.
     *
     * @return True se forem iguais, false caso contrário.
     */
    friend bool operator==(const ByteArray& left, const ByteArray& right);
    
    /**
     * @brief Compara dois ByteArray e retorna true se forem diferentes, false caso contrário.
     * 
     * @param left	Primeiro ByteArray da comparação.
     * @param right	Segundo ByteArray da comparação.
     *
     * @return True se forem diferentes, false caso contrário.
     */
    friend bool operator!=(const ByteArray& left, const ByteArray& right);

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
    friend ByteArray& operatorxor(const ByteArray& left, const ByteArray& right);

    /**
     * @brief Copia os dados do array de bytes \p from.
     * 
     * @param data		Array de bytes a ser copiado.
     * @param size	Tamanho do array de bytes a ser copiado.
     */
    void copyFrom(unsigned char* from, unsigned int size);

    /**
     * @brief Copia os dados do ByteArray para \p to.
     * 
     * @param to 				O ByteArray de destino.
     * @param toOffset			O offset de onde começar a copiar no destino.
     * @param fromOffset		O offset de onde começar a copiar da origem.
     * @param fromNumberOfBytes	O número de bytes a ser copiado da origem.
     *
     * @throw std::out_of_range se qualquer limite da origem ou destino for quebrado.
     */
    void copyTo(ByteArray& to, unsigned int toOffset, unsigned int fromOffset, unsigned int fromNumberOfBytes) const;

    /**
     * @brief Retorna um std::istringstream representando o ByteArray.
     *
     * Os dados do ByteArray são copiados para o std::istringstream.
     *
     * @return O std::istringstream.
     */
	std::istringstream* toInputStringStream() const;

    /**
     * @brief Modifica o ponteiro de memória do ByteArray para um já alocado, sem copiá-lo.
     * 
     * O ponteiro será deletado quando o ByteArray for destruído.
     *
     * @param data	O array de bytes para ser gerenciado pelo ByteArray.
     * @param size	O tamanho do array de bytes.
     */
    void setDataPointer(unsigned char* data, unsigned int size);
    void setDataPointer(const unsigned char* data, unsigned int size);

    /**
     * @return Um ponteiro const para o array de bytes gerenciado pelo ByteArray.
     */
    const unsigned char* getConstDataPointer() const;

    /**
     * @return Um ponteiro para o array de bytes gerenciado pelo ByteArray.
     */
    unsigned char* getDataPointer();

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
     * Os dados são copiados para a std::string.
     *
     * Essa função garante que a string é terminada em \0.
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
    
    ASN1_OCTET_STRING* getAsn1OctetString() const;

    /**
     * @brief Sobrescreve os dados do ByteArray.
     *
     * @param useRandomBytes Indica que o ByteArray deve ser sobrescrito com dados
     * aleatórios, caso contrário ele será sobrescrito com zeros.
     */
    virtual void burn(bool useRandomBytes = false);

private:
    unsigned int size;
    unsigned int originalSize;
    unsigned char* m_data;
};

#endif /*BYTEARRAY_H_*/
