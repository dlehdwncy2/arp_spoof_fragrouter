import struct

class Packet:

  def __init__( self, raw ):
    self._eth = Eth( raw[:14] )

    if self._eth.type == 0x0800:
      self.analyze_ip( raw[14:] )

  def analyze_ip( self, raw ):
    self._ip = Ip( raw )
    if self._ip.type == 17:
      self.analyze_udp( raw[20:] )

  def analyze_udp( self, raw ):
    self._udp = Udp( raw )

  @property
  def eth( self ):
    return self._eth

  @property
  def ip( self ):
    return self._ip

  @property
  def udp( self ):
    return self._udp

class Udp:

  def __init__( self, raw=None ):
    if raw != None:
      self._src = raw[:2]
      self._dst = raw[2:4]
      self._length = raw[4:6]
      self._chksum = raw[6:8]
      self._data = raw[8:]

  @property
  def header( self ):
    return self._src + self._dst + self._length + self._chksum + self._data

  @property
  def src( self ):
    (src,) = struct.unpack('!H', self._src )
    return src

  @property
  def dst( self ):
    (dst,) = struct.unpack('!H', self._dst )
    return dst

  @property
  def length( self ):
    (length,) = struct.unpack('!H', self._length )
    return length

  @property
  def chksum( self ):
    (chk,) = struct.unpack('!H', self._chksum )
    return chk

  @property
  def data( self ):
    return self._data.decode( errors='ignore' )


class Ip:

 

  def __init__( self, raw=None ):

    if raw != None:

      self._ver_and_len = raw[:1]

      self._service = raw[1:2]

      self._total = raw[2:4]

      self._id = raw[4:6]

      self._flag_and_offset = raw[6:8]

      self._ttl = raw[8:9]

      self._type = raw[9:10]

      self._chksum = raw[10:12]

      self._src = raw[12:16]

      self._dst = raw[16:20]

 

  @property

  def header( self ):

    return self._ver_and_len + self._service + self._total + self._id + \

           self._flag_and_offset + self._ttl + self._type + self._chksum + \

           self._src + self._dst

 

  @property

  def ver( self ):

    (ver,) = struct.unpack('!B', self._ver_and_len )

    ver = ver >> 4

    return ver

 

  @property

  def length( self ):

    (len,) = struct.unpack('!B', self._ver_and_len )

    len = ( len & 0x0F ) << 2

    return len

 

  @property

  def service( self ):

    (service,) = struct.unpack('!B', self._service )

    return service

 

  @property

  def total( self ):

    (total,) = struct.unpack('!H', self._total )

    return total

 

  @property

  def id( self ):

    (id,) = struct.unpack('!H', self._id )

    return id

 

  @property

  def flag( self ):


class Eth:

  def __init__( self, raw=None ):
    if raw != None:
      self._dst = raw[:6]
      self._src = raw[6:12]
      self._type = raw[12:14]

  @property
  def header( self ):
    return self._dst + self._src + self._type

  @property
  def dst( self ):
    dst = struct.unpack('!6B', self._dst )
    dst = '%02x:%02x:%02x:%02x:%02x:%02x' % dst
    return dst

  @property
  def src( self ):
    src = struct.unpack('!6B', self._src )
    src = '%02x:%02x:%02x:%02x:%02x:%02x' % src
    return src

  @property
  def type( self ):
    (type,) = struct.unpack('!H', self._type )
    return type
