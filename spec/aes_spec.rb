require 'spec_helper'
require 'tempfile'

describe "the aes cipher" do

  before do
    @cipher = Kingslayer::AES.new("password")
  end
  subject { @cipher }
  
  it { should respond_to :password }
  it { should respond_to :size }
  it { should respond_to :cipher }
  it { should respond_to :iter }
  it { should respond_to :hexkey }
  it { should respond_to :hexiv }

  it "should default to 1 iteration" do
    @cipher.iter.should == 1  
  end

  describe "setup for encryption should generate non nil iv and key" do
    let!(:secret_text) { "some funky secret text" } 
    before { @cipher.e(secret_text) }
    its(:hexkey) { should_not be_nil }
    its(:hexiv) { should_not be_nil }
  end
    
  it "should encrypt text and be compatible with OpenSSL CLI" do
    secret_text = "Made with Gibberish"
    encrypted = @cipher.e(secret_text)
    key = @cipher.hexkey
    iv = @cipher.hexiv
    from_openssl = `echo "#{encrypted}" | openssl enc -d -aes-256-cbc -a -K #{key} -iv #{iv}`
    from_openssl.should == secret_text
  end

  it "should encrypt file and be compatible with OpenSSL CLI" do
    source_file_path = "spec/fixtures/secret.txt"
    encrypted_file = Tempfile.new('secret.txt.enc')
    @cipher.ef(source_file_path, encrypted_file.path)
    decrypted_file = Tempfile.new('secret.txt')
    `openssl aes-256-cbc -d -in #{encrypted_file.path} -out #{decrypted_file.path} -k password`
    FileUtils.cmp(source_file_path, decrypted_file.path).should be_true
  end

  it "when salt is not specified, encrypted text from repeated calls should not be the same" do
    secret_text = "Made with Gibberish"
    encrypted1 = @cipher.e(secret_text)
    encrypted2 = @cipher.e(secret_text)
    encrypted1.should_not == encrypted2
  end

  it "when salt is specified, encrypted text from repeated calls (with same salt) be the same" do
    secret_text = "Made with Gibberish"
    salt = 'NaClNaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    encrypted2 = @cipher.e(secret_text, {:salt => salt})
    encrypted1.should == encrypted2
  end

  it "when supplied salt is too long, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = 'NaClNaClNaClNaClNaClNaClNaClNaClNaClNaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "when supplied salt is too short, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = 'NaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "when number is supplied for salt, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = 42
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "when idiotic value is supplied for salt, text should still encrypt/decrypt correctly" do
    secret_text = "Made with Gibberish"
    salt = {:whoknew => "I'm an idiot"}
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "should decrypt base64 encoded data from the OpenSSL CLI" do
    secret_text = "Made with Gibberish"
    from_openssl = `echo #{secret_text} | openssl enc -aes-256-cbc -a -k password`
    decrypted_text = @cipher.d(from_openssl).chomp
    decrypted_text.should == secret_text
  end

  it "should decrypt file encrypted with OpenSSL CLI" do
    source_file_path = "spec/fixtures/secret.txt"
    encrypted_file = Tempfile.new('secret.txt.enc')
    `openssl aes-256-cbc -salt -in #{source_file_path} -out #{encrypted_file.path} -k password`
    decrypted_file = Tempfile.new('secret.txt')
    @cipher.df(encrypted_file.path, decrypted_file.path)
    FileUtils.cmp(source_file_path, decrypted_file.path).should == true
  end

  it "should throw correct exception when decryption string is too short" do
    expect{@cipher.d("short")}.to raise_error(ArgumentError)
  end

  describe 'stream encryption' do

    it 'encrypts a file' do
      File.open('spec/openssl/plaintext.txt', 'rb') do |in_file|
        File.open(Tempfile.new('gib'), 'wb') do |enc_file|
          @cipher.encrypt_stream in_file, enc_file, salt: 'SOMESALT'
          File.read(enc_file.path).should == File.read('spec/openssl/plaintext.aes')
        end
      end
    end

    it 'decrypts a file' do
      File.open('spec/openssl/plaintext.aes', 'rb') do |in_file|
        File.open(Tempfile.new('gib'), 'wb') do |dec_file|
          @cipher.decrypt_stream in_file, dec_file
          File.read(dec_file.path).should == File.read('spec/openssl/plaintext.txt')
        end
      end
    end

  end

end
