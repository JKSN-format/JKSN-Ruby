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
#require 'jksn'


class Integer
  def to_jksn
    jksn_create.to_s
  end
  
  def jksn_create(*args)
    if (0x00..0x0A).cover? self
      #return (self + 0x10).chr
      return JKSN::JKSNValue.new(self, self | 0x10)
    elsif (-128..127).cover? self
      #return [0x1d, self].pack('cc')
      return JKSN::JKSNValue.new(self, 0x1d, __jksn_encode(1))
    elsif (-32767..32768).cover? self
      #return [0x1c, self].pack('cs>')
      return JKSN::JKSNValue.new(self, 0x1c, __jksn_encode(2))
    elsif (0x20000000..0x7FFFFFFF).cover?(self) or (-0x80000000..-0x20000000).cover?(self)
      return jksn_create_bignum
    elsif (-2147483648...0x20000000).cover? self
      #return [0x1b, self].pack('cl>')
      return JKSN::JKSNValue.new(self, 0x1b, __jksn_encode(4))
    else
      return jksn_create_bignum
    end
  end

  def __jksn_encode(length)
    case length
    when 0
      return __jksn_encode_bignum
    when 1
      return (self & 0x00FF).chr
    when 2
      return [self & 0x00FFFF].pack('S>')[0]
    when 4
      return [self & 0x00FFFFFFFF].pack('L>')[0]
    else
      raise ArgumentError.new
    end
  end

  private
  def jksn_create_bignum
    raise unless self != 0
    minus = (self < 0)
    return JKSN::JKSNValue.new(self, (minus ? 0x1e : 0x1f), self.abs.__jksn_encode_bignum)
  end

  def __jksn_encode_bignum(num)
    num = num.clone
    atoms = [num & 0x007F]
    num >>= 7
    while num != 0
      atoms.unshift((num & 0x007F) | 0x0080)
      num >>= 7
    end
    atoms.pack('C*')
  end

end

class TrueClass
  def to_jksn
    jksn_create.to_s
  end
  def jksn_create(*args)
    ::JKSN::JKSNValue.new(self, 0x03)
  end
end

class FalseClass
  def to_jksn
    jksn_create.to_s
  end
  def jksn_create(*args)
    ::JKSN::JKSNValue.new(self, 0x02)
  end
end

class NilClass
  def to_jksn
    jksn_create.to_s
  end
  def jksn_create(*args)
    ::JKSN::JKSNValue.new(self, 0x01)
  end
end

class Float
  def to_jksn
    jksn_create.to_s
  end
  def jksn_create(*args)
    return JKSN::JKSNValue.new(self, 0x20) if self.nan?
    case self.infinite?
    when 1
      return JKSN::JKSNValue.new(self, 0x2f)
    when -1
      return JKSN::JKSNValue.new(self, 0x2e)
    else
      return JKSN::JKSNValue.new(self, 0x2c, [self].pack('G')[0])
    end
  end
end

class String
  def to_jksn
    jksn_create.to_s
  end
  def jksn_create(state=nil)
    state = JKSN::EncoderState.from_state(state)
    if state.force_string_encoding == :blob || self.encoding == Encoding::ASCII_8BIT
      return jksn_create_blob
    else
      return jksn_create_unicode(state)
    end
  end

  def __jksn_djbhash(iv=0)
    self.each_byte.reduce(iv) do |a,b|
      ((a << 5) + b) & 0xFF
    end
  end

  private

  def jksn_create_blob
    if length <= 0xB
      result = JKSN::JKSNValue.new(self, 0x50 | length, '', self)
    elsif length <= 0xFF
      result = JKSN::JKSNValue.new(self, 0x5e, length.__jksn_encode(1), self)
    elsif length <= 0xFFFF
      result = JKSN::JKSNValue.new(self, 0x5d, length.__jksn_encode(2), self)
    else
      result = JKSN::JKSNValue.new(self, 0x5f, length.__jksn_encode(0), self)
    end
    result.data_hash = __jksn_djbhash
    return result
  end

  def jksn_create_unicode(state)

    case state.force_string_encoding
    when :utf8
      str = self.encode(Encoding::UTF_8)
      control, enclength = 0x40, str.length
    when :utf16
      str = self.encode(Encoding::UTF_16LE)
      control, enclength = 0x30, u16str.length << 1
    else
      u16str = self.encode(Encoding::UTF_16LE)
      u8str  = self.encode(Encoding::UTF_8)
      str, control, enclength = (u16str.length < u8str.length) ? [u16str, 0x30, u16str.length << 1] : [u8str, 0x40, u8str.length]
    end

    if enclength <= (control == 0x40 ? 0xc : 0xb)
      result = JKSN::JKSNValue.new(self, control | length, '', short)
    elsif enclength <= 0xFF
      result = JKSN::JKSNValue.new(self, control | 0x0e, length.__jksn_encode(1), short)
    elsif enclength <= 0xFFFF
      result = JKSN::JKSNValue.new(self, control | 0x0d, length.__jksn_encode(2), short)
    else
      result = JKSN::JKSNValue.new(self, control | 0x0f, length.__jksn_encode(0), short)
    end
    result.data_hash = short.__jksn_djbhash
    return result
  end
end

class Hash
  def to_jksn
    jksn_create.optimize.to_s
  end
  def jksn_create(state=nil)
    state = JKSN::EncoderState.from_state(state)
    if length <= 0xc
      result = JKSN::JKSNValue.new(self, 0x90 | length)
    elsif length <= 0xff
      result = JKSN::JKSNValue.new(self, 0x9e, length.__jksn_encode(1))
    elsif length <= 0xffff
      result = JKSN::JKSNValue.new(self, 0x9d, length.__jksn_encode(2))
    else
      result = JKSN::JKSNValue.new(self, 0x9f, length.__jksn_encode(0))
    end
    state.inc_depth
    self.each do |key, value|
      result.children << key.jksn_create(state)
      result.children << value.jksn_create(state)
    end
    state.dec_depth
    raise unless result.children.length == length * 2
    return result
  end
end


class Array
  def to_jksn
    jksn_create.optimize.to_s
  end
  def jksn_create(state=nil)
    state = JKSN::EncoderState.from_state(state)
    result = jksn_create_straight(state)
    return result if state.swapped_array_disabled?
    if __jksn_can_swap?
      result_swapped = jksn_create_swapped(state)
      result = result_swapped if result_swapped.length(3) < result.length(3)
    end
    return result
  end

  def __jksn_can_swap?
    columns = false
    self.each do |row|
      return false unless row.is_a? Hash
      columns = columns || (row.length != 0)
    end
    return columns
  end

  def jksn_create_straight(state=nil)
    state = JKSN::EncoderState.from_state(state)
    if length <= 0xc
      result = JKSN::JKSNValue.new(self, 0x80 | length)
    elsif length <= 0xff
      result = JKSN::JKSNValue.new(self, 0x8e, length.__jksn_encode(1))
    elsif length <= 0xffff
      result = JKSN::JKSNValue.new(self, 0x8d, length.__jksn_encode(2))
    else
      result = JKSN::JKSNValue.new(self, 0x8f, length.__jksn_encode(0))
    end
    state.inc_depth
    self.each do |i|
      result.children << i.jksn_create(state)
    end
    state.dec_depth
    raise unless result.children.length == length
    return result
  end

  def jksn_create_swapped(state=nil)
    state = JKSN::EncoderState.from_state(state)
    # row is Hash
    columns = self.map(&:keys).flatten(1).uniq
    if columns.length <= 0xc
      result = JKSN::JKSNValue.new(self, 0xa0 | columns.length)
    elsif columns.length <= 0xff
      result = JKSN::JKSNValue.new(self, 0xae, columns.length.__jksn_encode(1))
    elsif columns.length <= 0xffff
      result = JKSN::JKSNValue.new(self, 0xad, columns.length.__jksn_encode(2))
    else
      result = JKSN::JKSNValue.new(self, 0xa8f, columns.length.__jksn_encode(0))
    end
    state.inc_depth
    columns.each do |column|
      result.children << column.jksn_create(state)
      result.children << self.map{|row| row.fetch(column, JKSN::UnspecifiedValue)}.jksn_create(state)
    end
    state.dec_depth
    raise unless result.children.length == columns.length * 2
    return result
  end
end
