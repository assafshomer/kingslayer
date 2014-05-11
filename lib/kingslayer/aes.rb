module Kingslayer
  #   Handles AES encryption and decryption in a way that is compatible
  #   with OpenSSL.
  #
  #   Defaults to 256-bit CBC encryption, ideally you should leave it
  #   this way
  #
  # ## Basic Usage
  #
  # ### Encrypting
  #
  #     cipher = Kingslayer::AES.new('p4ssw0rd')
  #     cipher.encrypt("some secret text")
  #     #=> "U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=\n"
  #     cipher.encrypt_file("secret.txt", "secret.txt.enc")
  #
  # ### Decrypting
  #
  #     cipher = Kingslayer::AES.new('p4ssw0rd')
  #     cipher.decrypt(""U2FsdGVkX1/D7z2azGmmQELbMNJV/n9T/9j2iBPy2AM=\n"")
  #     #=> "some secret text"
  #     cipher.decrypt_file("secret.txt.enc", "secret.txt.enc.dec")
  #
  class AES

    attr_reader :password, :cipher, :iter, :hexkey, :hexiv

    def initialize(password, iter=1)
      @password = password
      @iter = iter
      @cipher = OpenSSL::Cipher::AES256.new('CBC')
    end

    def encrypt(data, opts={})
      salt = generate_salt(opts[:salt])
      key = generate_key(password,salt, iter)
      iv = cipher.random_iv
      setup_cipher(:encrypt, key, iv)
      e = cipher.update(data) + cipher.final
      e = "Salted__#{salt}#{iv}#{e}"
      opts[:binary] ? e : Base64.encode64(e)
    end
    alias :enc :encrypt
    alias :e :encrypt

    def decrypt(data, opts={})
      raise ArgumentError, 'Data is too short' unless data.length >= 16
      data = Base64.decode64(data) unless opts[:binary]
      salt = data[8..15]
      iv = data[16..31]
      data = data[32..-1]
      key = generate_key(password,salt, iter)
      setup_cipher(:decrypt, key, iv)
      cipher.update(data) + cipher.final
    end
    alias :dec :decrypt
    alias :d :decrypt

    def encrypt_file(plaintext_file_path, encrypted_file_path)
      plaintext=File.read(plaintext_file_path)
      ciphertext=encrypt(plaintext)      
      File.write(encrypted_file_path,ciphertext)
    end
    alias :enc_file :encrypt_file
    alias :ef :encrypt_file

    def decrypt_file(encrypted_file_path, decrypted_file_path)
      ciphertext = File.read(encrypted_file_path)
      plaintext = decrypt(ciphertext)
      File.write(decrypted_file_path, plaintext)
    end
    alias :dec_file :decrypt_file
    alias :df :decrypt_file

    private

      def generate_salt(supplied_salt)
        if supplied_salt
          return supplied_salt.to_s[0,8].ljust(8,'.')
        end
        s = ''
        8.times {s << rand(255).chr}
        s
      end

      def generate_key(password,salt, iter)
        digest=OpenSSL::Digest::SHA256.new
        len=digest.digest_length
        OpenSSL::PKCS5.pbkdf2_hmac(password,salt,iter,len,digest)
      end

      def setup_cipher(method, key, iv)
        cipher.send(method)
        cipher.key = key
        @hexkey = key.unpack('H*')[0]
        cipher.iv = iv
        @hexiv = iv.unpack('H*')[0]
      end

  end
end
