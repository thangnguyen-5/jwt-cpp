#pragma once
#define PICOJSON_USE_INT64
#include "picojson.h"
#include "base.h"
#include <set>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>

//If openssl version less than 1.1
#if OPENSSL_VERSION_NUMBER < 269484032
#define OPENSSL10
#endif

#ifndef JWT_CLAIM_EXPLICIT
#define JWT_CLAIM_EXPLICIT 1
#endif

namespace jwt {
	using date = std::chrono::system_clock::time_point;

	struct signature_verification_exception : public std::runtime_error {
		signature_verification_exception()
			: std::runtime_error("signature verification failed")
		{}
		explicit signature_verification_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit signature_verification_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct signature_generation_exception : public std::runtime_error {
		signature_generation_exception()
			: std::runtime_error("signature generation failed")
		{}
		explicit signature_generation_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit signature_generation_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct rsa_exception : public std::runtime_error {
		explicit rsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit rsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct ecdsa_exception : public std::runtime_error {
		explicit ecdsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit ecdsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct token_verification_exception : public std::runtime_error {
		token_verification_exception()
			: std::runtime_error("token verification failed")
		{}
		explicit token_verification_exception(const std::string& msg)
			: std::runtime_error("token verification failed: " + msg)
		{}
	};

	namespace error {
		enum class rsa_error {
			ok = 0,
			cert_load_failed = 10,
			get_pubkey_failed,
			write_pubkey_failed,
			convert_to_pem_failed,
			load_pubkey_bio_write,
			load_pubkey_bio_read
		};
		inline std::error_category& rsa_error_category() {
			class rsa_error_cat : public std::error_category
			{
			public:
				const char* name() const noexcept override { return "rsa_error"; };
				std::string message(int ev) const override {
					switch(static_cast<rsa_error>(ev)) {
					case rsa_error::ok: return "no error";
					case rsa_error::cert_load_failed: return "error loading cert into memory";
					case rsa_error::get_pubkey_failed: return "error getting public key from certificate";
					case rsa_error::write_pubkey_failed: return "error writing public key data in PEM format";
					case rsa_error::convert_to_pem_failed: return "failed to convert pubkey to pem";
					case rsa_error::load_pubkey_bio_write: return "failed to load public key: bio_write failed";
					case rsa_error::load_pubkey_bio_read: return "failed to load public key: PEM_read_bio_PUBKEY failed";
					default: return "unknown error code";
					}
				}
			};
			static rsa_error_cat cat = {};
			return cat;
		}
		inline std::error_code make_error_code(rsa_error e) {
			return {static_cast<int>(e), rsa_error_category()};
		}

		enum class signature_verification_error {
			ok = 0,
			invalid_signature = 10,
			create_context_failed,
			verifyinit_failed,
			verifyupdate_failed,
			verifyfinal_failed
		};
		inline std::error_category& signature_verification_error_category() {
			class verification_error_cat : public std::error_category
			{
			public:
				const char* name() const noexcept override { return "verification_error"; };
				std::string message(int ev) const override {
					switch(static_cast<signature_verification_error>(ev)) {
					case signature_verification_error::ok: return "no error";
					case signature_verification_error::invalid_signature: return "invalid signature";
					case signature_verification_error::create_context_failed: return "failed to verify signature: could not create context";
					case signature_verification_error::verifyinit_failed: return "failed to verify signature: VerifyInit failed";
					case signature_verification_error::verifyupdate_failed: return "failed to verify signature: VerifyUpdate failed";
					case signature_verification_error::verifyfinal_failed: return "failed to verify signature: VerifyFinal failed";
					default: return "unknown error code";
					}
				}
			};
			static verification_error_cat cat = {};
			return cat;
		}
		
		inline std::error_code make_error_code(signature_verification_error e) {
			return {static_cast<int>(e), signature_verification_error_category()};
		}

		enum class signature_generation_error {
			ok = 0,
			hmac_failed = 10,
			create_context_failed,
			signinit_failed,
			signupdate_failed,
			signfinal_failed,
			ecdsa_do_sign_failed,
			digestinit_failed,
			digestupdate_failed,
			digestfinal_failed,
			rsa_padding_failed,
			rsa_private_encrypt_failed
		};
		inline std::error_category& signature_generation_error_category() {
			class signature_generation_error_cat : public std::error_category
			{
			public:
				const char* name() const noexcept override { return "signature_generation_error"; };
				std::string message(int ev) const override {
					switch(static_cast<signature_generation_error>(ev)) {
					case signature_generation_error::ok: return "no error";
					case signature_generation_error::hmac_failed: return "hmac failed";
					case signature_generation_error::create_context_failed: return "failed to create signature: could not create context";
					case signature_generation_error::signinit_failed: return "failed to create signature: SignInit failed";
					case signature_generation_error::signupdate_failed: return "failed to create signature: SignUpdate failed";
					case signature_generation_error::signfinal_failed: return "failed to create signature: SignFinal failed";
					case signature_generation_error::ecdsa_do_sign_failed: return "failed to generate ecdsa signature";
					case signature_generation_error::digestinit_failed: return "failed to create signature: DigestInit failed";
					case signature_generation_error::digestupdate_failed: return "failed to create signature: DigestUpdate failed";
					case signature_generation_error::digestfinal_failed: return "failed to create signature: DigestFinal failed";
					case signature_generation_error::rsa_padding_failed: return "failed to create signature: RSA_padding_add_PKCS1_PSS_mgf1 failed";
					case signature_generation_error::rsa_private_encrypt_failed: return "failed to create signature: RSA_private_encrypt failed";
					default: return "unknown error code";
					}
				}
			};
			static signature_generation_error_cat cat = {};
			return cat;
		}
		
		inline std::error_code make_error_code(signature_generation_error e) {
			return {static_cast<int>(e), signature_generation_error_category()};
		}

		enum class decode_error {
			ok = 0,
			invalid_token_format,
			invalid_json
		};
		inline std::error_category& decode_error_category() {
			class decode_error_cat : public std::error_category
			{
			public:
				const char* name() const noexcept override { return "decode_error"; };
				std::string message(int ev) const override {
					switch(static_cast<decode_error>(ev)) {
					case decode_error::ok: return "no error";
					case decode_error::invalid_token_format: return "invalid token format";
					case decode_error::invalid_json: return "invalid json";
					default: return "unknown error code";
					}
				}
			};
			static decode_error_cat cat = {};
			return cat;
		}
		
		inline std::error_code make_error_code(decode_error e) {
			return {static_cast<int>(e), decode_error_category()};
		}

		inline void throw_if_error(std::error_code ec) {
			if(ec) {
				if(ec.category() == rsa_error_category())
					throw rsa_exception(ec.message());
				if(ec.category() == signature_verification_error_category())
					throw signature_verification_exception(ec.message());
				if(ec.category() == signature_generation_error_category())
					throw signature_generation_exception(ec.message());
				if(ec.category() == decode_error_category()) {
					if(static_cast<decode_error>(ec.value()) == decode_error::invalid_token_format) throw std::invalid_argument(ec.message());
					throw std::runtime_error(ec.message());
				}
				if(ec.category() == base64_error_category())
					throw std::runtime_error(ec.message());
			}
		}
	}
}
namespace std
{
	template <>
	struct is_error_code_enum<jwt::error::rsa_error> : true_type {};
	template <>
	struct is_error_code_enum<jwt::error::signature_verification_error> : true_type {};
	template <>
	struct is_error_code_enum<jwt::error::signature_generation_error> : true_type {};
	template <>
	struct is_error_code_enum<jwt::error::decode_error> : true_type {};
}
namespace jwt {
	namespace helper {
		/**
		 * Extract a public key from a pem certificate
		 * \param certstr Certificate to extract from
		 * \param pw Password of certificate
		 * \param ec std::error_code filled with details on error
		 * \return Extracted public key in pem format or empty string on error
		 */
		inline
		std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw, std::error_code& ec) {
			// TODO: Cannot find the exact version this change happended
#if OPENSSL_VERSION_NUMBER <= 0x1000114fL
			std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(const_cast<char*>(certstr.data()), certstr.size()), BIO_free_all);
#else
			std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(certstr.data(), certstr.size()), BIO_free_all);
#endif
			std::unique_ptr<BIO, decltype(&BIO_free_all)> keybio(BIO_new(BIO_s_mem()), BIO_free_all);

			std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);
			if (!cert) {
				ec = error::rsa_error::cert_load_failed;
				return "";
			}
			std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
			if(!key) {
				ec = error::rsa_error::get_pubkey_failed;
				return "";
			}
			if(!PEM_write_bio_PUBKEY(keybio.get(), key.get())) {
				ec = error::rsa_error::write_pubkey_failed;
				return "";
			}
			char* ptr = nullptr;
			auto len = BIO_get_mem_data(keybio.get(), &ptr);
			if(len <= 0 || ptr == nullptr) {
				ec = error::rsa_error::convert_to_pem_failed;
				return "";
			}
			ec.clear();
			std::string res(ptr, len);
			return res;
		}

		/**
		 * Extract a public key from a pem certificate
		 * \param certstr Certificate to extract from
		 * \param pw Password of certificate
		 * \return Extracted public key in pem format
		 * \throws rsa_exception on error
		 */
		inline
		std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw = "") {
			std::error_code ec;
			auto res = extract_pubkey_from_cert(certstr, pw, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * Load a pem public key from string.
		 * You can also supply a certificate in which case it will extract and load the certs public key.
		 * \param key Public key or certificate in pem format
		 * \param password Password used to decrypt key
		 * \param ec std::error_code filled with details on error
		 * \return OpenSSL EVP_PKEY wrapped in a shared_ptr or nullptr on error
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_public_key_from_string(const std::string& key, const std::string& password, std::error_code& ec) {
			std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
			if(key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
				auto epkey = helper::extract_pubkey_from_cert(key, password, ec);
				if(ec) return nullptr;
				if ((size_t)BIO_write(pubkey_bio.get(), epkey.data(), epkey.size()) != epkey.size()) {
					ec = error::rsa_error::load_pubkey_bio_write;
					return nullptr;
				}
			} else {
				if ((size_t)BIO_write(pubkey_bio.get(), key.data(), key.size()) != key.size()) {
					ec = error::rsa_error::load_pubkey_bio_write;
					return nullptr;
				}
			}
			
			std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)password.c_str()), EVP_PKEY_free);
			if (!pkey) {
				ec = error::rsa_error::load_pubkey_bio_read;
				return nullptr;
			}
			return pkey;
		}

		/**
		 * Load a pem public key from string.
		 * You can also supply a certificate in which case it will extract and load the certs public key.
		 * \param key Public key or certificate in pem format
		 * \param password Password used to decrypt key
		 * \return OpenSSL EVP_PKEY wrapped in a shared_ptr
		 * \throws rsa_exception on error
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_public_key_from_string(const std::string& key, const std::string& password = "") {
			std::error_code ec;
			auto res = load_public_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * Load a pem private key from string.
		 * \param key Private key in pem format
		 * \param password Password used to decrypt key
		 * \param ec std::error_code filled with details on error
		 * \return OpenSSL EVP_PKEY wrapped in a shared_ptr or nullptr on error
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_private_key_from_string(const std::string& key, const std::string& password, std::error_code& ec) {
			std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
			if ((size_t)BIO_write(privkey_bio.get(), key.data(), key.size()) != key.size()) {
				ec = error::rsa_error::load_pubkey_bio_write;
				return nullptr;
			}
			std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())), EVP_PKEY_free);
			if (!pkey) {
				ec = error::rsa_error::load_pubkey_bio_read;
				return nullptr;
			}
			return pkey;
		}

		/**
		 * Load a pem private key from string.
		 * \param key Private key in pem format
		 * \param password Password used to decrypt key
		 * \return OpenSSL EVP_PKEY wrapped in a shared_ptr
		 * \throws rsa_exception on error
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_private_key_from_string(const std::string& key, const std::string& password = "") {
			std::error_code ec;
			auto res = load_private_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}
	}

	namespace algorithm {
		/**
		 * "none" algorithm.
		 * 
		 * Returns and empty signature and checks if the given signature is empty.
		 */
		struct none {
			/// Return an empty string
			std::string sign(const std::string&) const {
				return "";
			}
			/// Return an empty string
			std::string sign(const std::string&, std::error_code& ec) const {
				ec.clear();
				return "";
			}
			/// Check if the given signature is empty. JWT's with "none" algorithm should not contain a signature.
			void verify(const std::string&, const std::string& signature) const {
				if (!signature.empty())
					throw signature_verification_exception();
			}
			void verify(const std::string&, const std::string& signature, std::error_code& ec) const {
				if (!signature.empty()) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
			}
			/// Get algorithm name
			std::string name() const {
				return "none";
			}
		};
		/**
		 * Base class for HMAC family of algorithms
		 */
		struct hmacsha {
			/**
			 * Construct new hmac algorithm
			 * \param key Key to use for HMAC
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			hmacsha(std::string key, const EVP_MD*(*md)(), const std::string& name)
				: secret(std::move(key)), md(md), alg_name(name)
			{}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec std::error_code filled with details on error
			 * \return HMAC signature for the given data or empty string on error
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				std::string res;
				res.resize(EVP_MAX_MD_SIZE);
				unsigned int len = res.size();
				if (HMAC(md(), secret.data(), secret.size(), (const unsigned char*)data.data(), data.size(), (unsigned char*)res.data(), &len) == nullptr) {
					ec = error::signature_generation_error::hmac_failed;
				}
				res.resize(len);
				return res;
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return HMAC signature for the given data
			 * \throws signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				std::error_code ec;
				auto res = sign(data, ec);
				error::throw_if_error(ec);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec std::error_code filled with details if an error occured
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				auto res = sign(data, ec);
				if(ec) return;
				bool matched = true;
				for (size_t i = 0; i < std::min<size_t>(res.size(), signature.size()); i++)
					if (res[i] != signature[i])
						matched = false;
				if (res.size() != signature.size())
					matched = false;
				if (!matched) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throws signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/// HMAC secrect
			const std::string secret;
			/// HMAC hash generator
			const EVP_MD*(*md)();
			/// Algorithmname
			const std::string alg_name;
		};
		/**
		 * Base class for RSA family of algorithms
		 */
		struct rsa {
			/**
			 * Construct new rsa algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			rsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), const std::string& name)
				: md(md), alg_name(name)
			{
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if(!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw rsa_exception("at least one of public or private key need to be present");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec std::error_code filled with details on error
			 * \return RSA signature for the given data or empty string on error
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx) {
					ec = error::signature_generation_error::create_context_failed;
					return "";
				}
				if (!EVP_SignInit(ctx.get(), md())) {
					ec = error::signature_generation_error::signinit_failed;
					return "";
				}

				std::string res;
				res.resize(EVP_PKEY_size(pkey.get()));
				unsigned int len = 0;

				if (!EVP_SignUpdate(ctx.get(), data.data(), data.size())) {
					ec = error::signature_generation_error::signupdate_failed;
					return "";
				}
				if (!EVP_SignFinal(ctx.get(), (unsigned char*)res.data(), &len, pkey.get())) {
					ec = error::signature_generation_error::signfinal_failed;
					return "";
				}

				res.resize(len);
				return res;
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return RSA signature for the given data
			 * \throws signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				std::error_code ec;
				auto res = sign(data, ec);
				error::throw_if_error(ec);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec std::error_code filled with details on error
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx) {
					ec = error::signature_verification_error::create_context_failed;
					return;
				}
				if (!EVP_VerifyInit(ctx.get(), md())) {
					ec = error::signature_verification_error::verifyinit_failed;
					return;
				}
				if (!EVP_VerifyUpdate(ctx.get(), data.data(), data.size())) {
					ec = error::signature_verification_error::verifyupdate_failed;
					return;
				}
				auto res = EVP_VerifyFinal(ctx.get(), (const unsigned char*)signature.data(), signature.size(), pkey.get());
				if (res == 0) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				} else if(res < 0) {
					ec = error::signature_verification_error::verifyfinal_failed;
					return;
				}
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throws signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/// OpenSSL structure containing converted keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator
			const EVP_MD*(*md)();
			/// Algorithmname
			const std::string alg_name;
		};
		/**
		 * Base class for ECDSA family of algorithms
		 */
		struct ecdsa {
			/**
			 * Construct new ecdsa algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			ecdsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), const std::string& name)
				: md(md), alg_name(name)
			{
				if (!public_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if(public_key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
						auto epkey = helper::extract_pubkey_from_cert(public_key, public_key_password);
						if ((size_t)BIO_write(pubkey_bio.get(), epkey.data(), epkey.size()) != epkey.size())
							throw ecdsa_exception("failed to load public key: bio_write failed");
					} else  {
						if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) != public_key.size())
							throw ecdsa_exception("failed to load public key: bio_write failed");
					}

					pkey.reset(PEM_read_bio_EC_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()), EC_KEY_free);
					if (!pkey)
						throw ecdsa_exception("failed to load public key: PEM_read_bio_EC_PUBKEY failed:" + std::string(ERR_error_string(ERR_get_error(), NULL)));
				}

				if (!private_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) != private_key.size())
						throw rsa_exception("failed to load private key: bio_write failed");
					pkey.reset(PEM_read_bio_ECPrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(private_key_password.c_str())), EC_KEY_free);
					if (!pkey)
						throw rsa_exception("failed to load private key: PEM_read_bio_ECPrivateKey failed");
				}
				if(!pkey)
					throw rsa_exception("at least one of public or private key need to be present");

				if(EC_KEY_check_key(pkey.get()) == 0)
					throw ecdsa_exception("failed to load key: key is invalid");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec std::error_code filled with details on error
			 * \return ECDSA signature for the given data or empty string on error
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				const std::string hash = generate_hash(data, ec);
				if(ec) return "";

				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>
					sig(ECDSA_do_sign((const unsigned char*)hash.data(), hash.size(), pkey.get()), ECDSA_SIG_free);
				if(!sig){
					ec = error::signature_generation_error::ecdsa_do_sign_failed;
					return "";
				}
#ifdef OPENSSL10

				return bn2raw(sig->r) + bn2raw(sig->s);
#else
				const BIGNUM *r;
				const BIGNUM *s;
				ECDSA_SIG_get0(sig.get(), &r, &s);
				return bn2raw(r) + bn2raw(s);
#endif
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return ECDSA signature for the given data
			 * \throws signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				std::error_code ec;
				auto res = sign(data, ec);
				error::throw_if_error(ec);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec std::error_code filled with details on error
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				const std::string hash = generate_hash(data, ec);
				auto r = raw2bn(signature.substr(0, signature.size() / 2));
				auto s = raw2bn(signature.substr(signature.size() / 2));

#ifdef OPENSSL10
				ECDSA_SIG sig;
				sig.r = r.get();
				sig.s = s.get();

				if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), &sig, pkey.get()) != 1) {
					ec = error::signature_verification_error::invalid_signature;
				}
#else
				ECDSA_SIG *sig = ECDSA_SIG_new();

				ECDSA_SIG_set0(sig, r.get(), s.get());

				if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), sig, pkey.get()) != 1) {
					ec = error::signature_verification_error::invalid_signature;
				}
#endif
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throws signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/**
			 * Convert a OpenSSL BIGNUM to a std::string
			 * \param bn BIGNUM to convert
			 * \return bignum as string
			 */
#ifdef OPENSSL10
			static std::string bn2raw(BIGNUM* bn)
#else
			static std::string bn2raw(const BIGNUM* bn)
#endif
			{
				std::string res;
				res.resize(BN_num_bytes(bn));
				BN_bn2bin(bn, (unsigned char*)res.data());
				if(res.size()%2 == 1 && res[0] == 0x00)
					return res.substr(1);
				return res;
			}
			/**
			 * Convert an std::string to a OpenSSL BIGNUM
			 * \param raw String to convert
			 * \return BIGNUM representation
			 */
			static std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(const std::string& raw) {
				if(static_cast<uint8_t>(raw[0]) >= 0x80) {
					std::string str(1, 0x00);
					str += raw;
					return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn((const unsigned char*)str.data(), str.size(), nullptr), BN_free);
				}
				return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn((const unsigned char*)raw.data(), raw.size(), nullptr), BN_free);
			}

			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \param ec std::error_code filled with details on error
			 * \return Hash of data
			 */
			std::string generate_hash(const std::string& data, std::error_code& ec) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
				if(EVP_DigestInit(ctx.get(), md()) == 0) {
					ec = error::signature_generation_error::digestinit_failed;
					return "";
				}
				if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0) {
					ec = error::signature_generation_error::digestupdate_failed;
					return "";
				}
				unsigned int len = 0;
				std::string res;
				res.resize(EVP_MD_CTX_size(ctx.get()));
				if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0) {
					ec = error::signature_generation_error::digestfinal_failed;
					return "";
				}
				res.resize(len);
				return res;
			}

			/// OpenSSL struct containing keys
			std::shared_ptr<EC_KEY> pkey;
			/// Hash generator function
			const EVP_MD*(*md)();
			/// Algorithmname
			const std::string alg_name;
		};

		/**
		 * Base class for PSS-RSA family of algorithms
		 */
		struct pss {
			/**
			 * Construct new pss algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			pss(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), const std::string& name)
				: md(md), alg_name(name)
			{
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if(!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw rsa_exception("at least one of public or private key need to be present");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec std::error_code filled with details on error
			 * \return PSS signature for the given data or empty string on error
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				auto hash = this->generate_hash(data, ec);
				if(ec) return "";

				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				const int size = RSA_size(key.get());

				std::string padded(size, 0x00);
				if (!RSA_padding_add_PKCS1_PSS_mgf1(key.get(), (unsigned char*)padded.data(), (const unsigned char*)hash.data(), md(), md(), -1)) {
					ec = error::signature_generation_error::rsa_padding_failed;
					return "";
				}

				std::string res(size, 0x00);
				if (RSA_private_encrypt(size, (const unsigned char*)padded.data(), (unsigned char*)res.data(), key.get(), RSA_NO_PADDING) < 0) {
					ec = error::signature_generation_error::rsa_private_encrypt_failed;
					return "";
				}
				return res;
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return PSS signature for the given data
			 * \throws signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				std::error_code ec;
				auto res = sign(data, ec);
				error::throw_if_error(ec);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec std::error_code filled with details on error
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				auto hash = this->generate_hash(data, ec);
				if(ec) return;

				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				const int size = RSA_size(key.get());
				
				std::string sig(size, 0x00);
				if(!RSA_public_decrypt(signature.size(), (const unsigned char*)signature.data(), (unsigned char*)sig.data(), key.get(), RSA_NO_PADDING)) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
				
				if(!RSA_verify_PKCS1_PSS_mgf1(key.get(), (const unsigned char*)hash.data(), md(), md(), (const unsigned char*)sig.data(), -1)) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throws signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return Algorithmname
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \param ec std::error_code filled with details on error
			 * \return Hash of data
			 */
			std::string generate_hash(const std::string& data, std::error_code& ec) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
				if(EVP_DigestInit(ctx.get(), md()) == 0) {
					ec = error::signature_generation_error::digestinit_failed;
					return "";
				}
				if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0) {
					ec = error::signature_generation_error::digestupdate_failed;
					return "";
				}
				unsigned int len = 0;
				std::string res;
				res.resize(EVP_MD_CTX_size(ctx.get()));
				if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0) {
					ec = error::signature_generation_error::digestfinal_failed;
					return "";
				}
				res.resize(len);
				return res;
			}
			
			/// OpenSSL structure containing keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator function
			const EVP_MD*(*md)();
			/// Algorithmname
			const std::string alg_name;
		};

		/**
		 * HS256 algorithm
		 */
		struct hs256 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs256(std::string key)
				: hmacsha(std::move(key), EVP_sha256, "HS256")
			{}
		};
		/**
		 * HS384 algorithm
		 */
		struct hs384 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs384(std::string key)
				: hmacsha(std::move(key), EVP_sha384, "HS384")
			{}
		};
		/**
		 * HS512 algorithm
		 */
		struct hs512 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs512(std::string key)
				: hmacsha(std::move(key), EVP_sha512, "HS512")
			{}
		};
		/**
		 * RS256 algorithm
		 */
		struct rs256 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit rs256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256")
			{}
		};
		/**
		 * RS384 algorithm
		 */
		struct rs384 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit rs384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384")
			{}
		};
		/**
		 * RS512 algorithm
		 */
		struct rs512 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit rs512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512")
			{}
		};
		/**
		 * ES256 algorithm
		 */
		struct es256 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit es256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256")
			{}
		};
		/**
		 * ES384 algorithm
		 */
		struct es384 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit es384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384")
			{}
		};
		/**
		 * ES512 algorithm
		 */
		struct es512 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit es512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512")
			{}
		};

		/**
		 * PS256 algorithm
		 */
		struct ps256 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit ps256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256")
			{}
		};
		/**
		 * PS384 algorithm
		 */
		struct ps384 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit ps384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384")
			{}
		};
		/**
		 * PS512 algorithm
		 */
		struct ps512 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param privat_key_password Password to decrypt private key pem.
			 */
			explicit ps512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512")
			{}
		};
	}

	/**
	 * Convenience wrapper for JSON value
	 */
	class claim {
		picojson::value val;
	public:
		enum class type {
			null,
			boolean,
			number,
			string,
			array,
			object,
			int64
		};

		claim()
			: val()
		{}
#if JWT_CLAIM_EXPLICIT
		explicit claim(std::string s)
			: val(std::move(s))
		{}
		explicit claim(const date& s)
			: val(int64_t(std::chrono::system_clock::to_time_t(s)))
		{}
		explicit claim(const std::set<std::string>& s)
			: val(picojson::array(s.cbegin(), s.cend()))
		{}
		explicit claim(const picojson::value& val)
			: val(val)
		{}
#else
		claim(std::string s)
			: val(std::move(s))
		{}
		claim(const date& s)
			: val(int64_t(std::chrono::system_clock::to_time_t(s)))
		{}
		claim(const std::set<std::string>& s)
			: val(picojson::array(s.cbegin(), s.cend()))
		{}
		claim(const picojson::value& val)
			: val(val)
		{}
#endif

		template<typename Iterator>
		claim(Iterator start, Iterator end)
			: val(picojson::array())
		{
			auto& arr = val.get<picojson::array>();
			for(; start != end; start++) {
				arr.push_back(picojson::value(*start));
			}
		}

		/**
		 * Get wrapped json object
		 * \return Wrapped json object
		 */
		picojson::value to_json() const {
			return val;
		}

		/**
		 * Get type of contained object
		 * \return Type
		 * \throws std::logic_error An internal error occured
		 */
		type get_type() const {
			if (val.is<picojson::null>()) return type::null;
			else if (val.is<bool>()) return type::boolean;
			else if (val.is<int64_t>()) return type::int64;
			else if (val.is<double>()) return type::number;
			else if (val.is<std::string>()) return type::string;
			else if (val.is<picojson::array>()) return type::array;
			else if (val.is<picojson::object>()) return type::object;
			else throw std::logic_error("internal error");
		}

		/**
		 * Get the contained object as a string
		 * \return content as string
		 * \throws std::bad_cast Content was not a string
		 */
		const std::string& as_string() const {
			if (!val.is<std::string>())
				throw std::bad_cast();
			return val.get<std::string>();
		}
		/**
		 * Get the contained object as a date
		 * \return content as date
		 * \throws std::bad_cast Content was not a date
		 */
		date as_date() const {
			return std::chrono::system_clock::from_time_t(as_int());
		}
		/**
		 * Get the contained object as an array
		 * \return content as array
		 * \throws std::bad_cast Content was not an array
		 */
		const picojson::array& as_array() const {
			if (!val.is<picojson::array>())
				throw std::bad_cast();
			return val.get<picojson::array>();
		}
		/**
		 * Get the contained object as a set of strings
		 * \return content as set of strings
		 * \throws std::bad_cast Content was not a set
		 */
		const std::set<std::string> as_set() const {
			std::set<std::string> res;
			for(auto& e : as_array()) {
				if(!e.is<std::string>())
					throw std::bad_cast();
				res.insert(e.get<std::string>());
			}
			return res;
		}
		/**
		 * Get the contained object as an integer
		 * \return content as int
		 * \throws std::bad_cast Content was not an int
		 */
		int64_t as_int() const {
			if (!val.is<int64_t>())
				throw std::bad_cast();
			return val.get<int64_t>();
		}
		/**
		 * Get the contained object as a bool
		 * \return content as bool
		 * \throws std::bad_cast Content was not a bool
		 */
		bool as_bool() const {
			if (!val.is<bool>())
				throw std::bad_cast();
			return val.get<bool>();
		}
		/**
		 * Get the contained object as a number
		 * \return content as double
		 * \throws std::bad_cast Content was not a number
		 */
		double as_number() const {
			if (!val.is<double>())
				throw std::bad_cast();
			return val.get<double>();
		}
	};

	/**
	 * Base class that represents a token payload.
	 * Contains Convenience accessors for common claims.
	 */
	class payload {
	protected:
		std::unordered_map<std::string, claim> payload_claims;
	public:
		/**
		 * Check if issuer is present ("iss")
		 * \return true if present, false otherwise
		 */
		bool has_issuer() const noexcept { return has_payload_claim("iss"); }
		/**
		 * Check if subject is present ("sub")
		 * \return true if present, false otherwise
		 */
		bool has_subject() const noexcept { return has_payload_claim("sub"); }
		/**
		 * Check if audience is present ("aud")
		 * \return true if present, false otherwise
		 */
		bool has_audience() const noexcept { return has_payload_claim("aud"); }
		/**
		 * Check if expires is present ("exp")
		 * \return true if present, false otherwise
		 */
		bool has_expires_at() const noexcept { return has_payload_claim("exp"); }
		/**
		 * Check if not before is present ("nbf")
		 * \return true if present, false otherwise
		 */
		bool has_not_before() const noexcept { return has_payload_claim("nbf"); }
		/**
		 * Check if issued at is present ("iat")
		 * \return true if present, false otherwise
		 */
		bool has_issued_at() const noexcept { return has_payload_claim("iat"); }
		/**
		 * Check if token id is present ("jti")
		 * \return true if present, false otherwise
		 */
		bool has_id() const noexcept { return has_payload_claim("jti"); }
		/**
		 * Get issuer claim
		 * \return issuer as string
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		const std::string& get_issuer() const { return get_payload_claim("iss").as_string(); }
		/**
		 * Get subject claim
		 * \return subject as string
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		const std::string& get_subject() const { return get_payload_claim("sub").as_string(); }
		/**
		 * Get audience claim
		 * \return audience as a set of strings
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a set (Should not happen in a valid token)
		 */
		std::set<std::string> get_audience() const { 
			auto aud = get_payload_claim("aud");
			if(aud.get_type() == jwt::claim::type::string) return { aud.as_string()};
			else return aud.as_set();
		}
		/**
		 * Get expires claim
		 * \return expires as a date in utc
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
		const date get_expires_at() const { return get_payload_claim("exp").as_date(); }
		/**
		 * Get not valid before claim
		 * \return nbf date in utc
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
		const date get_not_before() const { return get_payload_claim("nbf").as_date(); }
		/**
		 * Get issued at claim
		 * \return issued at as date in utc
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
		const date get_issued_at() const { return get_payload_claim("iat").as_date(); }
		/**
		 * Get id claim
		 * \return id as string
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		const std::string& get_id() const { return get_payload_claim("jti").as_string(); }
		/**
		 * Check if a payload claim is present
		 * \return true if claim was present, false otherwise
		 */
		bool has_payload_claim(const std::string& name) const noexcept { return payload_claims.count(name) != 0; }
		/**
		 * Get payload claim
		 * \return Requested claim
		 * \throws std::runtime_error If claim was not present
		 */
		const claim& get_payload_claim(const std::string& name) const {
			if (!has_payload_claim(name))
				throw std::runtime_error("claim not found");
			return payload_claims.at(name);
		}
		/**
		 * Get all payload claims
		 * \return map of claims
		 */
		std::unordered_map<std::string, claim> get_payload_claims() const { return payload_claims; }
	};

	/**
	 * Base class that represents a token header.
	 * Contains Convenience accessors for common claims.
	 */
	class header {
	protected:
		std::unordered_map<std::string, claim> header_claims;
	public:
		/**
		 * Check if algortihm is present ("alg")
		 * \return true if present, false otherwise
		 */
		bool has_algorithm() const noexcept { return has_header_claim("alg"); }
		/**
		 * Check if type is present ("typ")
		 * \return true if present, false otherwise
		 */
		bool has_type() const noexcept { return has_header_claim("typ"); }
		/**
		 * Check if content type is present ("cty")
		 * \return true if present, false otherwise
		 */
		bool has_content_type() const noexcept { return has_header_claim("cty"); }
		/**
		 * Check if key id is present ("kid")
		 * \return true if present, false otherwise
		 */
		bool has_key_id() const noexcept { return has_header_claim("kid"); }
		/**
		 * Get algorithm claim
		 * \return algorithm as string
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		const std::string& get_algorithm() const { return get_header_claim("alg").as_string(); }
		/**
		 * Get type claim
		 * \return type as a string
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		const std::string& get_type() const { return get_header_claim("typ").as_string(); }
		/**
		 * Get content type claim
		 * \return content type as string
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		const std::string& get_content_type() const { return get_header_claim("cty").as_string(); }
		/**
		 * Get key id claim
		 * \return key id as string
		 * \throws std::runtime_error If claim was not present
		 * \throws std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		const std::string& get_key_id() const { return get_header_claim("kid").as_string(); }
		/**
		 * Check if a header claim is present
		 * \return true if claim was present, false otherwise
		 */
		bool has_header_claim(const std::string& name) const noexcept { return header_claims.count(name) != 0; }
		/**
		 * Get header claim
		 * \return Requested claim
		 * \throws std::runtime_error If claim was not present
		 */
		const claim& get_header_claim(const std::string& name) const {
			if (!has_header_claim(name))
				throw std::runtime_error("claim not found");
			return header_claims.at(name);
		}
		/**
		 * Get all header claims
		 * \return map of claims
		 */
		std::unordered_map<std::string, claim> get_header_claims() const { return header_claims; }
	};

	class decoded_jwt;
	inline decoded_jwt decode(const std::string& token);
	inline std::unique_ptr<decoded_jwt> decode(const std::string& token, std::error_code& ec);

	/**
	 * Class containing all information about a decoded token
	 */
	class decoded_jwt : public header, public payload {
	protected:
		/// Unmodifed token, as passed to constructor
		const std::string token;
		/// Header part decoded from base64
		std::string header;
		/// Unmodified header part in base64
		std::string header_base64;
		/// Payload part decoded from base64
		std::string payload;
		/// Unmodified payload part in base64
		std::string payload_base64;
		/// Signature part decoded from base64
		std::string signature;
		/// Unmodified signature part in base64
		std::string signature_base64;

		friend decoded_jwt decode(const std::string& token);
		friend std::unique_ptr<decoded_jwt> decode(const std::string& token, std::error_code& ec);

		decoded_jwt(const std::string& t)
			: token(t)
		{}
	public:

		/**
		 * Get token string, as passed to constructor
		 * \return token as passed to constructor
		 */
		const std::string& get_token() const noexcept { return token; }
		/**
		 * Get header part as json string
		 * \return header part after base64 decoding
		 */
		const std::string& get_header() const noexcept { return header; }
		/**
		 * Get payload part as json string
		 * \return payload part after base64 decoding
		 */
		const std::string& get_payload() const noexcept { return payload; }
		/**
		 * Get signature part as json string
		 * \return signature part after base64 decoding
		 */
		const std::string& get_signature() const noexcept { return signature; }
		/**
		 * Get header part as base64 string
		 * \return header part before base64 decoding
		 */
		const std::string& get_header_base64() const noexcept { return header_base64; }
		/**
		 * Get payload part as base64 string
		 * \return payload part before base64 decoding
		 */
		const std::string& get_payload_base64() const noexcept { return payload_base64; }
		/**
		 * Get signature part as base64 string
		 * \return signature part before base64 decoding
		 */
		const std::string& get_signature_base64() const noexcept { return signature_base64; }

	};

	/**
	 * Builder class to build and sign a new token
	 * Use jwt::create() to get an instance of this class.
	 */
	class builder {
		std::unordered_map<std::string, claim> header_claims;
		std::unordered_map<std::string, claim> payload_claims;

		builder() {}
		friend builder create();
	public:
		/**
		 * Set a header claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_header_claim(const std::string& id, claim c) { header_claims[id] = std::move(c); return *this; }
		/**
		 * Set a payload claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_payload_claim(const std::string& id, claim c) { payload_claims[id] = std::move(c); return *this; }
		/**
		 * Set algorithm claim
		 * You normally don't need to do this, as the algorithm is automatically set if you don't change it.
		 * \param str Name of algorithm
		 * \return *this to allow for method chaining
		 */
		builder& set_algorithm(const std::string& str) { return set_header_claim("alg", claim(str)); }
		/**
		 * Set type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
		builder& set_type(const std::string& str) { return set_header_claim("typ", claim(str)); }
		/**
		 * Set content type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
		builder& set_content_type(const std::string& str) { return set_header_claim("cty", claim(str)); }
		/**
		 * Set key id claim
		 * \param str Key id to set
		 * \return *this to allow for method chaining
		 */
		builder& set_key_id(const std::string& str) { return set_header_claim("kid", claim(str)); }
		/**
		 * Set issuer claim
		 * \param str Issuer to set
		 * \return *this to allow for method chaining
		 */
		builder& set_issuer(const std::string& str) { return set_payload_claim("iss", claim(str)); }
		/**
		 * Set subject claim
		 * \param str Subject to set
		 * \return *this to allow for method chaining
		 */
		builder& set_subject(const std::string& str) { return set_payload_claim("sub", claim(str)); }
		/**
		 * Set audience claim
		 * \param l Audience set
		 * \return *this to allow for method chaining
		 */
		builder& set_audience(const std::set<std::string>& l) { return set_payload_claim("aud", claim(l)); }
		/**
		 * Set audience claim
		 * \param aud Single audience
		 * \return *this to allow for method chaining
		 */
		builder& set_audience(const std::string& aud) { return set_payload_claim("aud", claim(aud)); }
		/**
		 * Set expires at claim
		 * \param d Expires time
		 * \return *this to allow for method chaining
		 */
		builder& set_expires_at(const date& d) { return set_payload_claim("exp", claim(d)); }
		/**
		 * Set not before claim
		 * \param d First valid time
		 * \return *this to allow for method chaining
		 */
		builder& set_not_before(const date& d) { return set_payload_claim("nbf", claim(d)); }
		/**
		 * Set issued at claim
		 * \param d Issued at time, should be current time
		 * \return *this to allow for method chaining
		 */
		builder& set_issued_at(const date& d) { return set_payload_claim("iat", claim(d)); }
		/**
		 * Set id claim
		 * \param str ID to set
		 * \return *this to allow for method chaining
		 */
		builder& set_id(const std::string& str) { return set_payload_claim("jti", claim(str)); }

		/**
		 * Sign token and return result
		 * \param algo Instance of an algorithm to sign the token with
		 * \param ec std::error_code with details on error
		 * \return Final token as a string or empty string on error
		 */
		template<typename T>
		std::string sign(const T& algo, std::error_code& ec) const {
			picojson::object obj_header;
			obj_header["alg"] = picojson::value(algo.name());
			for (auto& e : header_claims) {
				obj_header[e.first] = e.second.to_json();
			}
			picojson::object obj_payload;
			for (auto& e : payload_claims) {
				obj_payload.insert({ e.first, e.second.to_json() });
			}

			auto encode = [](const std::string& data) {
				auto base = base::encode<alphabet::base64url>(data);
				auto pos = base.find(alphabet::base64url::fill());
				base = base.substr(0, pos);
				return base;
			};

			std::string header = encode(picojson::value(obj_header).serialize());
			std::string payload = encode(picojson::value(obj_payload).serialize());

			std::string token = header + "." + payload;

			token += "." + encode(algo.sign(token, ec));
			if(ec) return "";
			return token;
		}

		/**
		 * Sign token and return result
		 * \param algo Instance of an algorithm to sign the token with
		 * \return Final token as a string
		 * \throws Depending on the used algorithm a number of exception can be thrown.
		 */
		template<typename T>
		std::string sign(const T& algo) const {
			std::error_code ec;
			auto res = sign<T>(algo, ec);
			error::throw_if_error(ec);
			return res;
		}
	};

	/**
	 * Verifier class used to check if a decoded token contains all claims required by your application and has a valid signature.
	 */
	template<typename Clock>
	class verifier {
		struct algo_base {
			virtual ~algo_base() {}
			virtual void verify(const std::string& data, const std::string& sig) = 0;
			virtual void verify(const std::string& data, const std::string& sig, std::error_code& ec) = 0;
		};
		template<typename T>
		struct algo : public algo_base {
			T alg;
			explicit algo(T a) : alg(a) {}
			virtual void verify(const std::string& data, const std::string& sig) override {
				alg.verify(data, sig);
			}
			virtual void verify(const std::string& data, const std::string& sig, std::error_code& ec) override {
				alg.verify(data, sig, ec);
			}
		};

		/// Required claims
		std::unordered_map<std::string, claim> claims;
		/// Leeway time for exp, nbf and iat
		size_t default_leeway = 0;
		/// Instance of clock type
		Clock clock;
		/// Supported algorithms
		std::unordered_map<std::string, std::shared_ptr<algo_base>> algs;
	public:
		/**
		 * Constructor for building a new verifier instance
		 * \param c Clock instance
		 */
		explicit verifier(Clock c) : clock(c) {}

		/**
		 * Set default leeway to use.
		 * \param leeway Default leeway to use if not specified otherwise
		 * \return *this to allow chaining
		 */
		verifier& leeway(size_t leeway) { default_leeway = leeway; return *this; }
		/**
		 * Set leeway for expires at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for expires at.
		 * \return *this to allow chaining
		 */
		verifier& expires_at_leeway(size_t leeway) { return with_claim("exp", claim(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set leeway for not before.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for not before.
		 * \return *this to allow chaining
		 */
		verifier& not_before_leeway(size_t leeway) { return with_claim("nbf", claim(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set leeway for issued at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for issued at.
		 * \return *this to allow chaining
		 */
		verifier& issued_at_leeway(size_t leeway) { return with_claim("iat", claim(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set an issuer to check for.
		 * Check is casesensitive.
		 * \param iss Issuer to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_issuer(const std::string& iss) { return with_claim("iss", claim(iss)); }
		/**
		 * Set a subject to check for.
		 * Check is casesensitive.
		 * \param sub Subject to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_subject(const std::string& sub) { return with_claim("sub", claim(sub)); }
		/**
		 * Set an audience to check for.
		 * If any of the specified audiences is not present in the token the check fails.
		 * \param aud Audience to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_audience(const std::set<std::string>& aud) { return with_claim("aud", claim(aud)); }
		/**
		 * Set an id to check for.
		 * Check is casesensitive.
		 * \param id ID to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_id(const std::string& id) { return with_claim("jti", claim(id)); }
		/**
		 * Specify a claim to check for.
		 * \param name Name of the claim to check for
		 * \param c Claim to check for
		 * \return *this to allow chaining
		 */
		verifier& with_claim(const std::string& name, claim c) { claims[name] = c; return *this; }

		/**
		 * Add an algorithm available for checking.
		 * \param alg Algorithm to allow
		 * \return *this to allow chaining
		 */
		template<typename Algorithm>
		verifier& allow_algorithm(Algorithm alg) {
			algs[alg.name()] = std::make_shared<algo<Algorithm>>(alg);
			return *this;
		}

		/**
		 * Verify the given token.
		 * \param jwt Token to check
		 * \throws token_verification_exception Verification failed
		 */
		void verify(const decoded_jwt& jwt) const {
			const std::string data = jwt.get_header_base64() + "." + jwt.get_payload_base64();
			const std::string sig = jwt.get_signature();
			const std::string& algo = jwt.get_algorithm();
			if (algs.count(algo) == 0)
				throw token_verification_exception("wrong algorithm");
			algs.at(algo)->verify(data, sig);

			auto assert_claim_eq = [](const decoded_jwt& jwt, const std::string& key, const claim& c) {
				if (!jwt.has_payload_claim(key))
					throw token_verification_exception("decoded_jwt is missing " + key + " claim");
				auto& jc = jwt.get_payload_claim(key);
				if (jc.get_type() != c.get_type())
					throw token_verification_exception("claim " + key + " type mismatch");
				if (c.get_type() == claim::type::int64) {
					if (c.as_date() != jc.as_date())
						throw token_verification_exception("claim " + key + " does not match expected");
				}
				else if (c.get_type() == claim::type::array) {
					auto s1 = c.as_set();
					auto s2 = jc.as_set();
					if (s1.size() != s2.size())
						throw token_verification_exception("claim " + key + " does not match expected");
					auto it1 = s1.cbegin();
					auto it2 = s2.cbegin();
					while (it1 != s1.cend() && it2 != s2.cend()) {
						if (*it1++ != *it2++)
							throw token_verification_exception("claim " + key + " does not match expected");
					}
				}
				else if (c.get_type() == claim::type::string) {
					if (c.as_string() != jc.as_string())
						throw token_verification_exception("claim " + key + " does not match expected");
				}
				else throw token_verification_exception("internal error");
			};

			auto time = clock.now();

			if (jwt.has_expires_at()) {
				auto leeway = claims.count("exp") == 1 ? std::chrono::system_clock::to_time_t(claims.at("exp").as_date()) : default_leeway;
				auto exp = jwt.get_expires_at();
				if (time > exp + std::chrono::seconds(leeway))
					throw token_verification_exception("token expired");
			}
			if (jwt.has_issued_at()) {
				auto leeway = claims.count("iat") == 1 ? std::chrono::system_clock::to_time_t(claims.at("iat").as_date()) : default_leeway;
				auto iat = jwt.get_issued_at();
				if (time < iat - std::chrono::seconds(leeway))
					throw token_verification_exception("token expired");
			}
			if (jwt.has_not_before()) {
				auto leeway = claims.count("nbf") == 1 ? std::chrono::system_clock::to_time_t(claims.at("nbf").as_date()) : default_leeway;
				auto nbf = jwt.get_not_before();
				if (time < nbf - std::chrono::seconds(leeway))
					throw token_verification_exception("token expired");
			}
			for (auto& c : claims)
			{
				if (c.first == "exp" || c.first == "iat" || c.first == "nbf") {
					// Nothing to do here, already checked
				}
				else if (c.first == "aud") {
					if (!jwt.has_audience())
						throw token_verification_exception("token doesn't contain the required audience");
					auto aud = jwt.get_audience();
					auto expected = c.second.as_set();
					for (auto& e : expected)
						if (aud.count(e) == 0)
							throw token_verification_exception("token doesn't contain the required audience");
				}
				else {
					assert_claim_eq(jwt, c.first, c.second);
				}
			}
		}
	};

	/**
	 * Create a verifier using the given clock
	 * \param c Clock instance to use
	 * \return verifier instance
	 */
	template<typename Clock>
	verifier<Clock> verify(Clock c) {
		return verifier<Clock>(c);
	}

	/**
	 * Default clock class using std::chrono::system_clock as a backend.
	 */
	struct default_clock {
		std::chrono::system_clock::time_point now() const {
			return std::chrono::system_clock::now();
		}
	};

	/**
	 * Create a verifier using the default clock
	 * \return verifier instance
	 */
    inline
	verifier<default_clock> verify() {
		return verify<default_clock>({});
	}

	/**
	 * Return a builder instance to create a new token
	 */
    inline
	builder create() {
		return builder();
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \return Decoded token
	 * \throws std::invalid_argument Token is not in correct format
	 * \throws std::runtime_error Base64 decoding failed or invalid json
	 */
    inline
	decoded_jwt decode(const std::string& token) {
		std::error_code ec;
		auto r = decode(token, ec);
		error::throw_if_error(ec);
		if(!r) throw std::logic_error("internal error");
		return *r;
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \param ec std::error_code filled with details on error
	 * \return Decoded token or nullptr on error
	 */
    inline
	std::unique_ptr<decoded_jwt> decode(const std::string& token, std::error_code& ec) {
		auto hdr_end = token.find('.');
		if (hdr_end == std::string::npos) {
			ec = error::decode_error::invalid_token_format;
			return nullptr;
		}
		auto payload_end = token.find('.', hdr_end + 1);
		if (payload_end == std::string::npos) {
			ec = error::decode_error::invalid_token_format;
			return nullptr;
		}
		std::unique_ptr<decoded_jwt> result(new decoded_jwt(token));
		result->header = result->header_base64 = token.substr(0, hdr_end);
		result->payload = result->payload_base64 = token.substr(hdr_end + 1, payload_end - hdr_end - 1);
		result->signature = result->signature_base64 = token.substr(payload_end + 1);

		// Fix padding: JWT requires padding to get removed
		auto fix_padding = [](std::string& str) {
			switch (str.size() % 4) {
			case 1:
				str += alphabet::base64url::fill();
#ifdef __has_cpp_attribute
#if __has_cpp_attribute(fallthrough)
				[[fallthrough]];
#endif
#endif
			case 2:
				str += alphabet::base64url::fill();
#ifdef __has_cpp_attribute
#if __has_cpp_attribute(fallthrough)
				[[fallthrough]];
#endif
#endif
			case 3:
				str += alphabet::base64url::fill();
#ifdef __has_cpp_attribute
#if __has_cpp_attribute(fallthrough)
				[[fallthrough]];
#endif
#endif
			default:
				break;
			}
		};
		fix_padding(result->header);
		fix_padding(result->payload);
		fix_padding(result->signature);

		// TODO: Add error_code support to base header
		result->header = base::decode<alphabet::base64url>(result->header, ec);
		if(ec) return nullptr;
		result->payload = base::decode<alphabet::base64url>(result->payload, ec);
		if(ec) return nullptr;
		result->signature = base::decode<alphabet::base64url>(result->signature, ec);
		if(ec) return nullptr;

		auto parse_claims = [](const std::string& str, std::error_code& ec) {
			std::unordered_map<std::string, claim> res;
			picojson::value val;
			if (!picojson::parse(val, str).empty()) {
				ec = error::decode_error::invalid_json;
				return res;
			}

			for (auto& e : val.get<picojson::object>()) { res.insert({ e.first, claim(e.second) }); }

			return res;
		};

		result->header_claims = parse_claims(result->header, ec);
		if(ec) return nullptr;
		result->payload_claims = parse_claims(result->payload, ec);
		if(ec) return nullptr;
		return result;
	}
}
