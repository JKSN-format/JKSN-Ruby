# Copyright (c) 2014 StarBrilliant <m13253@hotmail.com>
#                and dantmnf       <dantmnf2@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms are permitted
# provided that the above copyright notice and this paragraph are
# duplicated in all such forms and that any documentation,
# advertising materials, and other materials related to such
# distribution and use acknowledge that the software was originally
# developed by StarBrilliant.
# The name of StarBrilliant may not be used to endorse or promote
# products derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

require 'stringio'
require 'json'
require 'zlib'
begin
  require 'openssl'
  JKSN::Digest = OpenSSL::Digest
rescue LoadError
  require 'digest'
end

module JKSN

  # Exception class raised during JKSN decoding
  class DecodeError < JKSNError
  end

  # Exception class raised during checksum verification when decoding
  class ChecksumError < DecodeError
  end

  class << self
    # load an object from a buffer
    def loads(*args)
      JKSNDecoder.new.loads(*args)
    end

    # Dump an object into a file object
    def load(*args)
      JKSNDecoder.new.load(*args)
    end
  end

  class JKSNDecoder
    def initialize
      @lastint = nil
      @texthash = {}
      @blobhash = {}
    end

    def parse(source, header=true)
      if io.is_a? String
        io = StringIO.new(s.b)
      end
      if header
        if (header_from_io = io.read(3)) != '!jk'.b
          io.seek(-header_from_io.length, IO::SEEK_CUR)
        end
      end
      return load_value(IODieOnEOF.new(io))
    end
    
    protected
    def load_value(io)
      loop do
        control = io.read(1).ord
        ctrlhi = control & 0xF0
        ctrllo = control & 0x0F
        #binding.pry
        case ctrlhi
        when 0x00 # Special values
          case control
          when 0x00, 0x01
            return nil
          when 0x02
            return false
          when 0x03
            return true
          when 0x0F
            s = load_value(io)
            raise DecodeError.new unless s.is_a? String
            return JSON.parse(s)
          end
        when 0x10 # Integers
          @lastint = case control
          when 0x10..0x1A
            control & 0x0F
          when 0x1B
            unsigned_to_signed(decode_int(io, 4), 32)
          when 0x1C
            unsigned_to_signed(decode_int(io, 2), 16)
          when 0x1D
            unsigned_to_signed(decode_int(io, 1), 8)
          when 0x1E
            -decode_int(io, 0)
          when 0x1F
            decode_int(io, 0)
          end
          return @lastint

        when 0x20 # Float point numbers
          case control
          when 0x20
            return Float::NAN
          when 0x2B
            raise NotImplementedError.new('this JKSN decoder does not support long double numbers')
          when 0x2C
            return io.read(8).unpack('G').first
          when 0x2D
            return io.read(4).unpack('g').first
          when 0x2E
            return -Float::INFINITY
          when 0x2F
            return Float::INFINITY
          end
        when 0x30 # UTF-16 strings
          case control
          when 0x30..0x3B
            return load_str(io, (control & 0xf) << 1, 'utf-16-le')
          when 0x3C
            hashvalue = io.readchar.ord
            if @texthash[hashvalue]
              return @texthash[hashvalue]
            else
              raise JKSNDecodeError.new('JKSN stream requires a non-existing hash: 0x%02x' % hashvalue)
            end
          when 0x3D
            return load_str(io, decode_int(io, 2) << 1, 'utf-16-le')
          when 0x3E
            return load_str(io, decode_int(io, 1) << 1, 'utf-16-le')
          when 0x3F
            return load_str(io, decode_int(io, 0) << 1, 'utf-16-le')
          end
        when 0x40 # UTF-8 strings
          len = get_length(io, control)
          return load_str(io, len, 'utf-8')
        when 0x50 # Blob strings
          len = get_length(io, control)
          case control
          when 0x50..0x5B, 0x5D..0x5F
            return load_str(len)
          when 0x5C
            hashvalue = io.readchar.ord
            if @texthash[hashvalue]
              return @texthash[hashvalue]
            else
              raise DecodeError.new('JKSN stream requires a non-existing hash: 0x%02x' % hashvalue)
            end
          end
        when 0x70 # Hashtable refreshers
          case control
          when 0x70
            @texthash.clear
            @blobhash.clear
          when 0x71..0x7F
            get_length(io, control).times { load_value(io) }
          end
        when 0x80 # Arrays
          len = get_length(io, control)
          return Array.new(len) { load_value(io) }
        when 0x90 # Objects
          len = get_length(io, control)
          result = {}
          len.times do
            key = load_value(io)
            value = load_value(io)
            result[key] = value
          end
          return result
        when 0xA0 # Row-col swapped arrays
          if control == 0xA0
            return UnspecifiedValue
          else
            return load_swapped_array(io, get_length(io, control))
          end
        when 0xC0
          case control
          when 0xC8 # Lengthless arrays
            result = []
            loop do
              item = load_value(io)
              if item != UnspecifiedValue
                result << item
              else
                return result
              end
            end
          when 0xCA # padding
            next
          end
        when 0xD0 # Delta encoded integers
          delta = case control
          when 0xD0..0xD5
            control & 0x0F
          when 0xD6..0xDA
            (control & 0x0F) - 11
          when 0xDB
            decode_int(io, 4)
          when 0xDC
            decode_int(io, 2)
          when 0xDD
            decode_int(io, 1)
          when 0xDE
            -decode_int(io, 0)
          when 0xDF
            decode_int(io, 0)
          end
          if @lastint
            return @lastint += delta
          else
            raise DecodeError.new('JKSN stream contains an invalid delta encoded integer')
          end
        when 0xF0 # Checksums
          chksum_length = [1, 4, 16, 20, 32, 64]
          hasher = [Digest::DJB, Digest::CRC32, Digest::MD5, Digest::SHA1, Digest::SHA256, Digest::SHA512]
          case control
          when 0xF0..0xF5
            i = control & 0x0F
            checksum = io.read(chksum_length[i])
            io = HashedIO.new(io, hasher[i])
            result = load_value(io)
            if io.digest == checksum
              return result
            else
              raise ChecksumError.new
            end
          when 0xF8..0xFD
            i = (control & 0x0F) - 0x08
            ioh = HashedIO.new(io, hasher[i])
            result = load_value(ioh)
            checksum = ioh.read(chksum_length[i])
            if io.digest == checksum
              return result
            else
              raise ChecksumError.new
            end
          when 0xFF
            load_value(io)
          end
        else
          raise DecodeError.new('cannot decode JKSN from byte 0x%02x' % control)
        end
        return result
      end

    end

    def decode_int(io, length)
      case length
      when 1
        return io.read(1).ord
      when 2
        return io.read(2).unpack('S>').first
      when 4
        return io.read(4).unpack('L>').first
      when 0
        result = 0
        thisbyte = -1
        while thisbyte & 0x80 != 0
          thisbyte = io.read(1).ord
          result = (result << 7) | (thisbyte & 0x7F)
        end
        return result
      else
        raise DecodeError.new
      end
    end

    def unsigned_to_signed(x, bits)
      x - ((x >> (bits - 1)) << bits)
    end

    def load_str(io, length, encoding=nil)
      buf = io.read length
      if encoding
        result = buf.force_encoding(encoding).encode(Encoding.default_external)
        @texthash[buf.__jksn_djbhash] = result
      else
        result = buf
        @blobhash[buf.__jksn_djbhash] = result
      end
      return result
    end

    def get_length(io, control)
      case control & 0x0F
      when 0x00..0x0C
        return control & 0x0F
      when 0x0D
        return decode_int(io, 2)
      when 0x0E
        return decode_int(io, 1)
      when 0x0F
        return decode_int(io, 0)
      else
        raise
      end
    end

    def load_swapped_array(io, column_length)
      result = []
      column_length.times do
        col_name = load_value io
        col_values = load_value io
        unless col_values.is_a? Array
          raise DecodeError.new('JKSN row-col swapped array requires an array but found a ' + col_values.class.name)
        end
        col_values.each_with_index do |value, i|
          result << [] if i == result.length
          result[i] << [col_name, value] if value != UnspecifiedValue
        end
      end
      result.map{|i| Hash[i] }.to_a
    end

    class IODieOnEOF
      def initialize(io)
        #warn 'nested IODieOnEOF' if io.is_a? IODieOnEOF
        @io = io
        @io.public_methods.each do |name|
          next if self.respond_to? name
          self.define_singleton_method(name) { |*args, &block| @io.__send__(name, *args, &block) }
        end
      end

      def read(length=nil, strbuf=nil)
        result = @io.read(length, strbuf)
        raise EOFError.new if result == nil or result == ""
        if length != nil
          raise EOFError.new if result.length < length
        end
        return result
      end
    end

    class HashedIO
      def initialize(io, digest_class)
        #warn 'nested HashedIO' if io.is_a? HashedIO
        @io = io
        @io.public_methods.each do |name|
          next if self.respond_to? name
          self.define_singleton_method(name) { |*args, &block| @io.__send__(name, *args, &block) }
        end
        @hasher = digest_class.new
      end

      def read(length=nil, strbuf=nil)
        result = @io.read(length, strbuf)
        if result
          @hasher << result
        end
        result
      end
      
      def digest
          @hasher.digest
      end
    end

    module Digest
      class CRC32
        def initialize
          @crc = Zlib::crc32
        end
        def update(str)
          @crc = Zlib::crc32_combine(@crc, Zlib::crc32(str), str.length)
          self
        end
        alias :<< :update
        def digest_length
          4
        end
        def digest(str=nil)
          if str
            initialize
            update str
            result = @crc.pack('L>').first
            initialize
            return result
          else
            return @crc.pack('L>').first
          end
        end
        def digest!
          result = @crc.pack('L>').first
          initialize
          result
        end
        def inspect # :nodoc:
          "#<%s %s>" % [self.class.name, '%08X' % @crc]
        end
      end

      class DJB
        def initialize
          @djb = ''.__jksn_djbhash
        end
        def update(str)
          @djb = str.__jksn_djbhash(@djb)
          self
        end
        alias :<< :update
        def digest_length
          1
        end
        def digest(str=nil)
          if str
            initialize
            update str
            result = @djb.chr
            initialize
            return result
          else
            return @djb.chr
          end
        end
        def digest!
          result = @djb.chr
          initialize
          result
        end
        def inspect # :nodoc:
          "#<%s %s>" % [self.class.name, '%02X' % @djb]
        end
      end
    end
  end
end
