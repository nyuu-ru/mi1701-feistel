/*
 * main.cc
 *
 *  Created on: 21 февр. 2022 г.
 *      Author: unyuu
 */

#include <iostream>
#include <fstream>
#include <cstdint>
#include <random>
#include <algorithm>
#include <utility>
#include <vector>
#include <array>
#include <tuple>
#include <functional>

const char *INPUT_FILENAME  = "input.txt";
const char *CRYPT_FILENAME  = "crypt.txt";
const char *OUTPUT_FILENAME = "output.txt";
const char *KEY1_FILENAME   = "key1.dat";
const char *KEY2_FILENAME   = "key2.dat";

constexpr uint16_t IV16 = 0x1234;
constexpr uint32_t IV32 = 0x12345678;
constexpr uint64_t IV64 = 0x1234567812345678ULL;

enum class EncryptionMode
{
	ECB, CBC, CTR
};

std::mt19937 random_gen;

std::mt19937 init_random()
{
	std::array<uint32_t, 624> seed_data;
	std::random_device rd;
	std::generate(
			std::begin(seed_data),
			std::end(seed_data),
			[&]() { return rd(); } );
	std::seed_seq seed(
			std::begin(seed_data),
			std::end(seed_data));
	return std::mt19937(seed);
}

/*
	Размер блока - 32 бита
	Размер подблока - 16 бит
	Количество раундов - 4
	Шифрующая функция:
		F(x, k) = (x <<< 3) ^ k
 */
constexpr int CIPHER1_ROUNDS = 4;
uint16_t cipher1_func(uint16_t x, uint16_t k)
{
	return ((x << 3) | (x >> 13)) ^ k;
}


constexpr int CIPHER2_ROUNDS = 128;
uint32_t cipher2_func(uint32_t x, uint32_t k)
{
	uint32_t y = ((x << 13) | (x >> (32-13-1))) + k;
	return (y >> 17) | (y << (32-17-1));
}


template <typename ST, typename KT>
auto feistel_round(const std::tuple<ST, ST> &block,
                   KT key,
                   const std::function<ST(ST, KT)> &func)
{
	return std::make_tuple<ST, ST>(
			static_cast<ST>(std::get<1>(block)),
			static_cast<ST>(std::get<0>(block) ^ func(
					std::get<1>(block), key)));
}

template <typename BT, typename ST>
auto unpack(BT block)
{
	return std::make_tuple<ST, ST>(
			static_cast<ST>(
					((static_cast<BT>(1) <<
							(sizeof(ST) * 8))-1) & block),
			static_cast<ST>(
					block >> (sizeof(ST) * 8) ));
}

template <typename BT, typename ST>
BT pack(const std::tuple<ST, ST> &block)
{
	return (static_cast<BT>(std::get<1>(block)) <<
			(sizeof(ST) * 8)) |
			std::get<0>(block);
}

void generate_key(const char *filename, size_t size_in_bytes)
{
	std::vector<char> data(size_in_bytes);
	std::generate(std::begin(data), std::end(data),
	              [&](){ return random_gen() & 0xff; });

	std::ofstream keyfile(filename, std::ios::binary);
	keyfile.write(&data[0], size_in_bytes);
	keyfile.close();
}

template <typename BT, typename ST, typename KT>
BT feistel_encrypt(BT block, const std::vector<KT> &key,
                   const std::function<ST(ST, KT)> &func)
{
	auto t = unpack<BT, ST>(block);
	auto rounds = key.size();
	typeof(rounds) r;
	for (r = 0; r < rounds; ++r) {
		t = feistel_round(t, key[r], func);
	}

	return pack<BT, ST>(std::make_tuple<ST,ST>(
			static_cast<ST>(std::get<1>(t)),
			static_cast<ST>(std::get<0>(t))));
}

template <typename BT, typename ST, typename KT>
BT feistel_decrypt(BT block, const std::vector<KT> &key,
                   const std::function<ST(ST, KT)> &func)
{
	auto t = unpack<BT, ST>(block);
	auto rounds = key.size();
	typeof(rounds) r;
	for (r = 0; r < rounds; ++r) {
		t = feistel_round(t, key[rounds - r - 1], func);
	}

	return pack<BT, ST>(std::make_tuple<ST,ST>(
			static_cast<ST>(std::get<1>(t)),
			static_cast<ST>(std::get<0>(t))));
}

template <typename BT, typename ST, typename KT, bool DE>
BT feistel_endecrypt(BT block, const std::vector<KT> &key,
                   const std::function<ST(ST, KT)> &func)
{
	auto t = unpack(block);
	auto rounds = key.size();
	typeof(rounds) r;
	for (r = 0; r < rounds; ++r) {
		KT k;
		if constexpr (DE == false)
			k = key[r];
		else
			k = key[rounds - r - 1];
		t = feistel_round(t, k, func);
	}

	return pack(std::make_tuple<ST,ST>(
			std::get<1>(t), std::get<0>(t)));
}

template <typename KT>
std::vector<KT> load_key(const char *filename)
{
	std::ifstream file(filename,
	                   std::ios::binary | std::ios::ate);
	size_t size = file.tellg();
	file.seekg(0);
	std::vector<KT> result(size);
	file.read(reinterpret_cast<char*>(&result[0]), size);
	file.close();
	return result;
}

// ECB
template <typename BT, typename ST, typename KT>
BT encrypt_ecb(BT block,
               const std::vector<KT> &key,
               const std::function<ST(ST,KT)> &func)
{
	return feistel_encrypt<BT, ST, KT>(block, key, func);
}

template <typename BT, typename ST, typename KT>
BT decrypt_ecb(BT block,
               const std::vector<KT> &key,
               const std::function<ST(ST,KT)> &func)
{
	return feistel_decrypt<BT, ST, KT>(block, key, func);
}

// CBC
template <typename BT, typename ST, typename KT>
BT encrypt_cbc(BT block,
               BT &iv,
               const std::vector<KT> &key,
               const std::function<ST(ST,KT)> &func)
{
	return iv = feistel_encrypt<BT, ST, KT>(block ^ iv, key, func);
}

template <typename BT, typename ST, typename KT>
BT decrypt_cbc(BT block,
               BT &iv,
               const std::vector<KT> &key,
               const std::function<ST(ST,KT)> &func)
{
	BT old_iv = iv;
	return feistel_decrypt<BT, ST, KT>((iv = block), key, func) ^ old_iv;
}


// CTR


template <typename BT, typename ST, typename KT,
	EncryptionMode MODE>
void encrypt_file(const char *input_filename,
                  const char *crypt_filename,
                  BT iv,
                  const std::vector<KT> &key,
                  const std::function<ST(ST,KT)> &func)
{
	std::ifstream input_file(input_filename,
	        std::ios::binary | std::ios::ate);
	std::ofstream crypt_file(crypt_filename, std::ios::binary);
	auto file_size = input_file.tellg();
	input_file.seekg(0);
	auto block_size = sizeof(BT);
	auto blocks = file_size / block_size;
	if (file_size % block_size != 0)
		blocks++;

	uint32_t orig_size = file_size;
	crypt_file.write(reinterpret_cast<char*>(&orig_size),
	        sizeof(orig_size));
	for (typeof (blocks) i = 0; i < blocks; ++i) {
		uint32_t current_block = 0;
		input_file.read(
				reinterpret_cast<char*>(&current_block),
		        sizeof(current_block));

		// Тут будет зашифрование текущего блока
		if constexpr (MODE == EncryptionMode::ECB) {
			current_block = encrypt_ecb<BT, ST, KT>(
					current_block, key, func);
		} else if constexpr (MODE == EncryptionMode::CBC) {
			current_block = encrypt_cbc<BT, ST, KT>(
					current_block, iv, key, func);
		} else {
			// Неизвестный режим
			current_block = encrypt_ecb<BT, ST, KT>(
					current_block, key, func);
		}

		crypt_file.write(
				reinterpret_cast<char*>(&current_block),
		        sizeof(current_block));
	}
}

template <typename BT, typename ST, typename KT, EncryptionMode MODE>
void decrypt_file(const char *crypt_filename,
                  const char *output_filename,
                  BT iv,
                  const std::vector<KT> &key,
                  const std::function<ST(ST,KT)> &func)
{
	std::ifstream crypt_file(crypt_filename,
	        std::ios::binary);
	std::ofstream output_file(output_filename,
	        std::ios::binary);
	uint32_t orig_size;
	crypt_file.read(reinterpret_cast<char*>(&orig_size),
	        sizeof(orig_size));
	auto block_size = sizeof(BT);
	auto blocks = orig_size / block_size;
	if (orig_size % block_size != 0)
		blocks++;

	for (typeof (blocks) i = 0; i < blocks; ++i) {
		uint32_t current_block = 0;
		crypt_file.read(
				reinterpret_cast<char*>(&current_block),
		        sizeof(current_block));

		// Тут будет расшифрование текущего блока
		if constexpr (MODE == EncryptionMode::ECB) {
			current_block = decrypt_ecb<BT, ST, KT>(
					current_block, key, func);
		} else if constexpr (MODE == EncryptionMode::CBC) {
			current_block = decrypt_cbc<BT, ST, KT>(
					current_block, iv, key, func);
		} else {
			// Неизвестный режим, используем ECB
			current_block = decrypt_ecb<BT, ST, KT>(
					current_block, key, func);
		}

		size_t to_write = block_size;
		if (orig_size < block_size)
			to_write = orig_size;
		output_file.write(
				reinterpret_cast<char*>(&current_block),
		        to_write);
		orig_size -= to_write;
	}
}

void test1()
{
	generate_key(KEY1_FILENAME,
			CIPHER1_ROUNDS * sizeof(uint16_t));
	generate_key(KEY2_FILENAME,
	             CIPHER1_ROUNDS * sizeof(uint16_t));
	auto key1 = load_key<uint16_t>(KEY1_FILENAME);
	auto key2 = load_key<uint16_t>(KEY2_FILENAME);
	encrypt_file<uint32_t, uint16_t, uint16_t, EncryptionMode::ECB>(
			INPUT_FILENAME, CRYPT_FILENAME,
			IV32, key1, cipher1_func);
	decrypt_file<uint32_t, uint16_t, uint16_t, EncryptionMode::ECB>(
			CRYPT_FILENAME, OUTPUT_FILENAME,
			IV32, key1, cipher1_func);
}

void test2()
{
	generate_key(KEY1_FILENAME,
			CIPHER2_ROUNDS * sizeof(uint32_t));
	generate_key(KEY2_FILENAME,
	        CIPHER2_ROUNDS * sizeof(uint32_t));
	auto key1 = load_key<uint32_t>(KEY1_FILENAME);
	auto key2 = load_key<uint32_t>(KEY2_FILENAME);
	encrypt_file<uint64_t, uint32_t, uint32_t, EncryptionMode::ECB>(
			INPUT_FILENAME, CRYPT_FILENAME,
			IV64, key1, cipher2_func);
	decrypt_file<uint64_t, uint32_t, uint32_t, EncryptionMode::ECB>(
			CRYPT_FILENAME, OUTPUT_FILENAME,
			IV64, key1, cipher2_func);
}

int main()
{
	random_gen = init_random();

	test2();
	return 0;
}


