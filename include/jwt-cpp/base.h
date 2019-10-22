#pragma once
#include <string>
#include <array>
#include <system_error>

namespace jwt {
	namespace error {
		enum class base64_error {
			ok = 0,
			invalid_input_too_much_fill,
			invalid_input_data_size_not_multiple_of_4,
			invalid_input_char_not_in_alphabet,
		};
		inline std::error_category& base64_error_category() {
			class base64_error_cat : public std::error_category
			{
			public:
				const char* name() const noexcept override { return "base64_error"; };
				std::string message(int ev) const override {
					switch(static_cast<base64_error>(ev)) {
					case base64_error::ok: return "no error";
					case base64_error::invalid_input_too_much_fill: return "invalid input: too much fill bytes";
					case base64_error::invalid_input_data_size_not_multiple_of_4: return "invalid input: datasize is not a multiple of 4";
					case base64_error::invalid_input_char_not_in_alphabet: return "invalid input: received char not in alphabet";
					default: return "unknown error code";
					}
				}
			};
			static base64_error_cat cat = {};
			return cat;
		}
		
		inline std::error_code make_error_code(base64_error e) {
			return {static_cast<int>(e), base64_error_category()};
		}
	}
}
namespace std
{
	template <>
	struct is_error_code_enum<jwt::error::base64_error> : true_type {};
}
namespace jwt {
	namespace alphabet {
		struct base64 {
			static const std::array<char, 64>& data() {
                            static std::array<char, 64> data = {
                                {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'}};
                            return data;
			};
			static const std::string& fill() {
				static std::string fill = "=";
				return fill;
			}
		};
		struct base64url {
			static const std::array<char, 64>& data() {
                            static std::array<char, 64> data = {
                                {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'}};
                            return data;
			};
			static const std::string& fill() {
				static std::string fill = "%3d";
				return fill;
			}
		};
	}

	class base {
	public:
		template<typename T>
		static std::string encode(const std::string& bin) {
			std::error_code ec;
			auto res = encode(bin, T::data(), T::fill(), ec);
			if(ec) throw std::runtime_error(ec.message());
			return res;
		}
		template<typename T>
		static std::string decode(const std::string& base) {
			std::error_code ec;
			auto res = decode(base, T::data(), T::fill(), ec);
			if(ec) throw std::runtime_error(ec.message());
			return res;
		}

		template<typename T>
		static std::string encode(const std::string& bin, std::error_code& ec) {
			return encode(bin, T::data(), T::fill(), ec);
		}
		template<typename T>
		static std::string decode(const std::string& base, std::error_code& ec) {
			return decode(base, T::data(), T::fill(), ec);
		}

	private:
		static std::string encode(const std::string& bin, const std::array<char, 64>& alphabet, const std::string& fill, std::error_code& ec) {
			size_t size = bin.size();
			std::string res;

			// clear incomplete bytes
			size_t fast_size = size - size % 3;
			for (size_t i = 0; i < fast_size;) {
				uint32_t octet_a = (unsigned char)bin[i++];
				uint32_t octet_b = (unsigned char)bin[i++];
				uint32_t octet_c = (unsigned char)bin[i++];

				uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

				res += alphabet[(triple >> 3 * 6) & 0x3F];
				res += alphabet[(triple >> 2 * 6) & 0x3F];
				res += alphabet[(triple >> 1 * 6) & 0x3F];
				res += alphabet[(triple >> 0 * 6) & 0x3F];
			}

			if (fast_size == size)
				return res;

			size_t mod = size % 3;

			uint32_t octet_a = fast_size < size ? (unsigned char)bin[fast_size++] : 0;
			uint32_t octet_b = fast_size < size ? (unsigned char)bin[fast_size++] : 0;
			uint32_t octet_c = fast_size < size ? (unsigned char)bin[fast_size++] : 0;

			uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

			switch (mod) {
			case 1:
				res += alphabet[(triple >> 3 * 6) & 0x3F];
				res += alphabet[(triple >> 2 * 6) & 0x3F];
				res += fill;
				res += fill;
				break;
			case 2:
				res += alphabet[(triple >> 3 * 6) & 0x3F];
				res += alphabet[(triple >> 2 * 6) & 0x3F];
				res += alphabet[(triple >> 1 * 6) & 0x3F];
				res += fill;
				break;
			default:
				break;
			}

			return res;
		}

		static std::string decode(const std::string& base, const std::array<char, 64>& alphabet, const std::string& fill, std::error_code& ec) {
			size_t size = base.size();

			size_t fill_cnt = 0;
			while (size > fill.size()) {
				if (base.substr(size - fill.size(), fill.size()) == fill) {
					fill_cnt++;
					size -= fill.size();
					if(fill_cnt > 2) {
						ec = error::base64_error::invalid_input_too_much_fill;
						return "";
					}
				}
				else break;
			}

			if ((size + fill_cnt) % 4 != 0) {
				ec = error::base64_error::invalid_input_data_size_not_multiple_of_4;
				return "";
			}

			size_t out_size = size / 4 * 3;
			std::string res;
			res.reserve(out_size);

			auto get_sextet = [&](size_t offset, std::error_code& ec) {
				for (size_t i = 0; i < alphabet.size(); i++) {
					if (alphabet[i] == base[offset])
						return i;
				}
				ec = error::base64_error::invalid_input_char_not_in_alphabet;
				return static_cast<size_t>(0);
			};

			
			size_t fast_size = size - size % 4;
			for (size_t i = 0; i < fast_size && !ec;) {
				uint32_t sextet_a = get_sextet(i++, ec);
				uint32_t sextet_b = get_sextet(i++, ec);
				uint32_t sextet_c = get_sextet(i++, ec);
				uint32_t sextet_d = get_sextet(i++, ec);

				uint32_t triple = (sextet_a << 3 * 6)
					+ (sextet_b << 2 * 6)
					+ (sextet_c << 1 * 6)
					+ (sextet_d << 0 * 6);

				res += (triple >> 2 * 8) & 0xFF;
				res += (triple >> 1 * 8) & 0xFF;
				res += (triple >> 0 * 8) & 0xFF;
			}
			
			if(ec) return "";

			if (fill_cnt == 0)
				return res;

			uint32_t triple = (get_sextet(fast_size, ec) << 3 * 6)
				+ (get_sextet(fast_size + 1, ec) << 2 * 6);

			switch (fill_cnt) {
			case 1:
				triple |= (get_sextet(fast_size + 2, ec) << 1 * 6);
				res += (triple >> 2 * 8) & 0xFF;
				res += (triple >> 1 * 8) & 0xFF;
				break;
			case 2:
				res += (triple >> 2 * 8) & 0xFF;
				break;
			default:
				break;
			}
			
			if(ec) return "";

			return res;
		}
	};
}
