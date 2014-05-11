require 'spec_helper'
require 'tempfile'

describe "the aes cipher" do
  let!(:secret_text) { 'Some funky secret 1234567890  66 text !@#%&*()$ +*(_P)&*()*%^%$&%!~@$#~`' }
  let!(:source_file_path) { "spec/fixtures/secret.txt" }
  before do
    @cipher = Kingslayer::AES.new("password")
  end
  subject { @cipher }
  
  it { should respond_to :password }
  it { should respond_to :cipher }
  it { should respond_to :iter }
  it { should respond_to :hexkey }
  it { should respond_to :hexiv }

  it "should default to 1 iteration" do
    @cipher.iter.should == 1  
  end

  describe "setup for encryption should generate non nil iv and key" do
    before { @cipher.e(secret_text) }
    its(:hexkey) { should_not be_nil }
    its(:hexiv) { should_not be_nil }
  end

  it "should be compatible with OpenSSL upto initial garbage" do
    encrypted = @cipher.e(secret_text)
    hexkey = @cipher.hexkey
    hexiv = @cipher.hexiv
    from_openssl = `echo "#{encrypted}" | openssl enc -d -aes-256-cbc -a -K #{hexkey} -iv #{hexiv}`
    # from_openssl.chars.select(&:valid_encoding?).join.should =~ /#{secret_text}/
    clean = from_openssl.chars.select(&:valid_encoding?).join
    regex = /#{Regexp.escape(secret_text)}/
    start_position = clean.index(regex)    
    clean[start_position..-1].should == secret_text
  end

  it "should encrypt/decrypt text correctly" do
    encrypted = @cipher.e(secret_text)
    @cipher.d(encrypted).should == secret_text
  end

  describe "text encryption/decryptioin should work with iterations" do
    let!(:strong) { Kingslayer::AES.new("password",100000) }
    let!(:enc) { strong.e(secret_text) }
    it { strong.d(enc).should == secret_text }
  end

  describe "text encryption/decryptioin should work with different instances" do
    let!(:encryptor) { Kingslayer::AES.new("foobar",10) }
    let!(:decryptor) { Kingslayer::AES.new("foobar",10) }
    let!(:enc) { encryptor.e(secret_text) }
    it { decryptor.d(enc).should == secret_text }
  end

  it "adding iterations should make things slower" do
    weak = Kingslayer::AES.new("password",1)
    strong = Kingslayer::AES.new("password",100000)
    a=Time.now
    foo = strong.e(secret_text)
    b=Time.now
    bar = weak.e(secret_text)
    c=Time.now
    ((b-a)/(c-b)).should > 1000
  end

  describe "file encryption/decryption should work" do
    let!(:encrypted_file_path) { Tempfile.new('secret.txt.enc').path }
    let!(:decrypted_file_path) { Tempfile.new('secret.txt.enc.dec').path }
    before do
      @cipher.ef(source_file_path, encrypted_file_path)
      @cipher.df(encrypted_file_path, decrypted_file_path)
    end
    it { FileUtils.cmp(source_file_path,decrypted_file_path).should be_true }
  end

  describe "file encryption/decryption should work with iterations" do
    let!(:strong) { Kingslayer::AES.new("password",100) }
    let!(:encrypted_file_path) { Tempfile.new('secret.txt.enc').path }
    let!(:decrypted_file_path) { Tempfile.new('secret.txt.enc.dec').path }
    before do
      strong.ef(source_file_path,encrypted_file_path)
      strong.df(encrypted_file_path, decrypted_file_path)
    end
    it { FileUtils.cmp(source_file_path,decrypted_file_path).should be_true }
  end

  describe "file encryption/decryption" do
    let!(:strong) { Kingslayer::AES.new("password",10) }
    let!(:wrong_itr) { Kingslayer::AES.new("password", 9) }
    let!(:wrong_pwd) { Kingslayer::AES.new("passwOrd", 10) }
    let!(:good_dec) { Kingslayer::AES.new("password",10) }
    let!(:encrypted_file_path) { Tempfile.new('secret.txt.enc').path }
    let!(:decrypted_file_path) { Tempfile.new('secret.txt.enc.dec').path }
    let!(:decrypted_wrong_itr_file_path) { Tempfile.new('secret.txt.enc.dec2').path }
    let!(:decrypted_wrong_pwd_file_path) { Tempfile.new('secret.txt.enc.dec3').path }
    before do
      strong.ef(source_file_path,encrypted_file_path)      
    end
    it "should not raise an error when using a well instantiated decryptor" do
      expect {good_dec.df(encrypted_file_path, decrypted_file_path)}.not_to raise_error      
    end    
    it "should raise an error when decrypting with a KS instantiated with the wrong number of iterations" do
      expect {wrong_itr.df(encrypted_file_path, decrypted_wrong_itr_file_path)}.to raise_error('bad decrypt')      
    end
    it "should raise an error when decrypting with a KS instantiated with the wrong pwd" do
      expect {wrong_pwd.df(encrypted_file_path, decrypted_wrong_pwd_file_path)}.to raise_error('bad decrypt')      
    end
  end


  it "should encrypt file and be compatible with OpenSSL upto initial garbage" do    
    encrypted_file_path = Tempfile.new('secret.txt.enc').path
    @cipher.ef(source_file_path, encrypted_file_path)
    decrypted_file_path = Tempfile.new('secret.txt.enc.dec').path
    clean_file_path = Tempfile.new('clean.dec').path
    `openssl aes-256-cbc -d -in #{encrypted_file_path} -out #{decrypted_file_path} -K #{@cipher.hexkey} -iv #{@cipher.hexiv} -a`
    clean = File.read(decrypted_file_path).chars.select(&:valid_encoding?).join
    secret_text = File.read(source_file_path)
    regex = /#{Regexp.escape(secret_text)}/
    start_position = clean.index(regex)
    File.write(clean_file_path,clean[start_position..-1])
    FileUtils.cmp(source_file_path, clean_file_path).should be_true
  end

  describe "encrypted text from repeated calls " do
    let!(:encrypted1) { @cipher.e(secret_text) }
    let!(:encrypted2) { @cipher.e(secret_text) }
    let!(:encrypted3) { @cipher.e(secret_text, salt: 'foobar') }
    let!(:encrypted4) { @cipher.e(secret_text, salt: 'foobar') }
    it "should not be the same" do
      encrypted1.should_not == encrypted2
    end
    it "should not be the same even if using the same salt (due to random IV)" do
      encrypted3.should_not == encrypted4
    end
  end

  it "when supplied salt is too long, text should still encrypt/decrypt correctly" do
    salt = 'NaClNaClNaClNaClNaClNaClNaClNaClNaClNaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "when supplied salt is too short, text should still encrypt/decrypt correctly" do
    salt = 'NaCl'
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "when number is supplied for salt, text should still encrypt/decrypt correctly" do
    salt = 42
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "when idiotic value is supplied for salt, text should still encrypt/decrypt correctly" do
    salt = {:whoknew => "I'm an idiot"}
    encrypted1 = @cipher.e(secret_text, {:salt => salt})
    @cipher.d(encrypted1).should == secret_text
  end

  it "should throw correct exception when decryption string is too short" do
    expect{@cipher.d("short")}.to raise_error(ArgumentError)
  end

end
