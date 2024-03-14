require 'ffi'

module DPAPI
  extend FFI::Library
  ffi_lib 'Crypt32'

  class EncryptError < StandardError; end
  class DecryptError < StandardError; end

  class DataBlob < FFI::Struct
    layout :cbData, :uint32,
           :pbData, :pointer

    def initialize(blob=nil)
      super(nil)
      self.data = blob unless blob.nil?
    end

    def data
      self[:pbData].get_bytes(0, self[:cbData])
    end

    def data=(blob)
      self[:pbData] = FFI::MemoryPointer.from_string(blob)
      self[:cbData] = blob.bytesize
    end
  end

  attach_function :CryptProtectData,
                  [:pointer, :string, :pointer, :pointer, :pointer, :uint32, :pointer],
                  :bool

  def self.encrypt(plaintext, entropy=nil, flags = [], desc=nil)
    ciphertext_blob = DataBlob.new

    CryptProtectData(DataBlob.new(plaintext),
                     desc,
                     entropy.nil? ? nil : DataBlob.new(entropy),
                     nil,
                     nil,
                     flags.reduce(0, :|),
                     ciphertext_blob) or
      raise EncryptError
    ciphertext_blob.data
  end

  attach_function :CryptUnprotectData,
                  [:pointer, :pointer, :pointer, :pointer, :pointer, :uint32, :pointer],
                  :bool

 def self.decrypt(ciphertext, entropy=nil, flags=[])
  plaintext_blob  = DataBlob.new
  desc = FFI::MemoryPointer.new(:pointer, 256)

  begin
    CryptUnprotectData(DataBlob.new(ciphertext),
                       desc,
                       entropy.nil? ? nil : DataBlob.new(entropy),
                       nil,
                       nil,
                       flags.reduce(0, :|),
                       plaintext_blob) or raise DecryptError
  rescue DecryptError => e
    raise DecryptError, "DPAPI decryption error: #{e.message}"
  end

  decrypted_key = plaintext_blob.data
  puts "Decrypted Key: #{decrypted_key}"
  
  [decrypted_key,
   desc.read_pointer.nil? ? nil : desc.read_pointer.read_string
  ]
end
end
