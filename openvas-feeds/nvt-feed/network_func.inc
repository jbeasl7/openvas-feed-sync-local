# SPDX-FileCopyrightText: 2002 Michel Arboi
# SPDX-FileCopyrightText: New code since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Checks if the 'Network type' preference of global_settings.nasl is set to 'Private LAN'.
#
# @note You need to include "global_settings.nasl" in your VT if you want to use this function.
#
# @return TRUE if the preference is set to 'Private LAN', FALSE otherwise.
#
function is_private_lan() {

  local_var network_type;

  network_type = get_kb_item( "global_settings/network_type" );
  if( network_type ) {
    if( "Private LAN" >< network_type )
      return TRUE;
  }

  return FALSE;
}

# @brief Test if address is on a Private LAN, reserved or not routable address.
#
# @param addr The (optional IPv4/IPv6 address to test)
#
# @note You need to include "global_settings.nasl" in your VT if you want to use this function.
#
# @return TRUE if the tested address is on a Private LAN, reserved or not routable address.
#         FALSE otherwise and NULL if an invalid IPv4/IPV6 address was passed to the addr
#         parameter.
#
function is_private_addr( addr ) {

  local_var addr;
  local_var all_addr_private, all_addr_public, network_type, a;

  all_addr_private = FALSE;
  all_addr_public  = FALSE;

  network_type = get_kb_item( "global_settings/network_type" );
  if( network_type ) {
    if( "Private LAN" >< network_type )
      all_addr_private = TRUE;
    else if( "Internet" >< network_type || "Public LAN" >< network_type )
      all_addr_public = TRUE;
  }

  if( all_addr_private || islocalhost() )
    return TRUE;

  if( all_addr_public && ! islocalhost() )
    return FALSE;

  if( ! addr ) {
    a = get_host_ip();
  } else {
    a = addr;
    if( a !~ "^[0-9a-z]+:" && a !~ "^0*[0-9]+\." ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#is_private_addr: Invalid IPv4/IPv6 address passed to 'addr' parameter: " + addr );
      return NULL;
    }
  }

  # nb: The next checks are for the "Mixed" configuration in network_type

  # nb: Don't use TARGET_IS_IPV6 because the IP address might be passed via the 'addr' parameter as well.
  if( ":" >< a ) {

    # Unique local address (ULA): https://en.wikipedia.org/wiki/Unique_local_address
    if( a =~ "^f[cd][0-9a-f]+:" )
      return TRUE;

  } else {

    # Localhost + RFC1918
    if( a =~ "^0*(127|10)\.[0-9]+\.[0-9]+\.[0-9]+" )
      return TRUE;

    # RFC 1918 + Link local (RFC 3330)
    if( a =~ "^0*(192\.0*168|169\.0*254)\.[0-9]+\.[0-9]+" )
      return TRUE;

    # RFC 1918
    if( a =~ "^0*172\.0*(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+" )
      return TRUE;

    # TEST-NET - RFC 3330
    if( a =~ "^0*192\.0*0\.0*2\.[0-9]+" )
      return TRUE;

    # RFC 2544
    if( a =~ "^0*192\.0*1[89]\.[0-9]+\.[0-9]+" )
      return TRUE;
  }

  return FALSE;
}

# @brief test if address is on a WAN (Internet) or Public LAN
#
# @param addr the (optional IP address to test)
#
# @note You need to include "global_settings.nasl" in your VT if you want to use this function.
#
# @return TRUE if the tested address is on a WAN (Internet) or Public LAN,
#         FALSE otherwise.
#
function is_public_addr( addr ) {

  local_var addr;

  if( islocalhost() )
    return FALSE;

  if( islocalnet() && ! is_private_addr( addr:addr ) )
    return TRUE;

  if( is_private_addr( addr:addr ) )
    return FALSE;

  if( ! is_private_addr( addr:addr ) )
    return TRUE;

  # nb: We shouldn't end up here, nevertheless we're returning FALSE.
  # This makes sure that we're not reporting a false positive for VTs
  # reporting a publicly accessible service were its actually not known
  # if the service is publicly accessible.
  return FALSE;
}

function test_udp_port( port, data, retries ) {

  local_var ip, udp, srcaddr, dstaddr, srcport, r, f, i, n, len, icmp, sp, dp, port, data, retries;

  if( ! port ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#test_udp_port" );

  if( retries <= 0 ) {
    n = 6;
  } else {
    n = retries;
  }

  if( isnull( data ) ) data = "";

  for( i = 0; i < n; i ++ ) {

    srcaddr = this_host();
    dstaddr = get_host_ip();
    srcport = 1024 + rand() % 64512;

    ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0,
                          ip_len:20, ip_id:0,
                          ip_p:IPPROTO_UDP, ip_ttl:255, ip_off:0,
                          ip_src:srcaddr, ip_dst:dstaddr );

    udp = forge_udp_packet( ip:ip, uh_sport:srcport, uh_dport:port,
                            uh_ulen:8 + strlen( data ), data:data );

    f = strcat( "src host ", dstaddr, " and dst host ", srcaddr,
    " and ( (udp and src port ", port, " and dst port ", srcport, ") or (",
    " icmp and icmp[0] = 3 and icmp[1] = 3))" );
    r = send_packet( udp, pcap_timeout:1, pcap_active:TRUE, pcap_filter:f );
    if( r ) {
      if( ord( r[9] ) == 17) { # udp
        return 2;
      } else {
        ##dump( ddata:r, dtitle:"sniffed" );
        len = ( ord( r[0] ) & 0xF );
        len *= 4;
        icmp = substr( r, len );
        ##dump( ddata:icmp, dtitle:"icmp" );
        ip = substr( icmp, 8 ); # Original datagram
        ##dump( ddata:ip, dtitle:"ip" );
        len = ( ord( ip[0] ) & 0xF );
        len *= 4;
        udp = substr( ip, len );
        sp = ord( udp[0] ) * 256 + ord( udp[1] );
        dp = ord( udp[2] ) * 256 + ord( udp[3] );
        if( srcport == sp && port == dp )
          return 0;
      }
    }
  }
  return 1;
}

function ip_checksum( data ) {

  local_var sum, i, n, data;

  if( isnull( data ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#ip_checksum" );

  n = strlen( data );
  sum = 0;
  for( i = 0; i < n - 1; i += 2 ) {
    sum = sum + ord( data[i] ) * 256 + ord( data[i+1] );
  }
  if( i < n ) {
    sum += ord(data[i]);
  }
  sum = ( sum >>> 16 ) + ( sum & 0xffff );
  sum += ( sum >>> 16 );
  sum = ( ~sum ) & 0xFFFF;
  return raw_string( sum % 256, sum / 256 );
}

function ms_since_midnight() {

  local_var s;

  s = unixtime();
  s %= 86400;

  return 1000 * s;
}

function htonl( n ) {

  local_var i, j, s, n;

  if( isnull( n ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#n#-#htonl" );

  j = n; # We do not want to modify a global variable, just in case.
  for( i = 0; i < 4; i ++ ) {
    s[i] = j & 0xFF;
    j >>>= 8;
  }
  return raw_string( s[3], s[2], s[1], s[0] );
}

function htons( n ) {

  local_var n;

  if( isnull( n ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#n#-#htons" );

  return raw_string( ( n >>> 8 ) & 0xFF, n & 0xFF );
}

function ntohl( n ) {

  local_var n;

  if( ! n ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#n#-#ntohl" );

  if( strlen( n ) != 4 ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#ntohl: invalid parameter / length (should be 4)" );
    return;
  }
  return( ord( n[0] ) << 24 ) | ( ord( n[1] ) << 16 ) | ( ord( n[2] ) << 8) | ord( n[3] );
}

## This function will return TRUE if UDP port is alive and
## return FALSE if udp port is not reachable
function check_udp_port_status( dport ) {

  local_var dport, sport, ip_pkt, udp_pkt, filter, res;

  if( ! dport ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dport#-#check_udp_port_status" );

  sport = rand() % 64512 + 1024;
  ip_pkt = forge_ip_packet( ip_hl:5, ip_v:4, ip_tos:0,
                            ip_len:20, ip_id:31337, ip_off:0,
                            ip_ttl:64, ip_p:IPPROTO_UDP, ip_src:this_host() );

  udp_pkt = forge_udp_packet( ip:ip_pkt, uh_sport:sport,
                              uh_dport:dport, uh_ulen:8 );

  ## Filter to check source host address and port and destination host address and port
  ## Also checking Destination host unreachable and Destination port unreachable
  filter = string( "src host ", get_host_ip(), " and dst host ", this_host(),
                   " and icmp and (icmp[0] == 3 and icmp[1] == 3 and icmp[28:2]==",
                   sport, " and icmp[30:2]==", dport, ")" );

  ## If UDP port is not reachable then it will return ICMP packet back
  ## i.e which will be having status code for Destination host unreachable
  ## and Destination port unreachable
  res = send_packet( udp_pkt, pcap_active:TRUE, pcap_filter:filter );

  ## Return TRUE if udp port is alive and return FALSE if udp port is not reachable
  if( res != NULL ) {
    return FALSE;
  } else {
    return TRUE;
  }
}

# @brief Tests if the remote Radius Server is alive.
#
# @param port The port of the remove Radius Server
#
# @return TRUE if the Radius Server is alive/available, FALSE otherwise
#         and NULL if no port was passed to the port parameter.
function is_radius_alive( port ) {

  local_var port;
  local_var vt_strings, username, data, soc, buf;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#is_radius_alive" );
    return NULL;
  }

  vt_strings = get_vt_strings();

  username = vt_strings["default"];
  data = raw_string( 0x40, 0xfa, 0xb3, 0x17, 0x23, 0xfd, 0xe5, 0x7f, 0x4a, 0x02,
                     0x74, 0x55, 0x15, 0x0c, 0x45, 0xeb ) +
         raw_string( 0x01, ( strlen( username ) + 2 ) ) +
         username +
         raw_string( 0x02, 0x12, 0xfa, 0x4d, 0xb1, 0x43, 0x69, 0xd5,
                     0x69, 0x8b, 0x1f, 0x30, 0xea, 0xf4, 0x54, 0x45, 0x1e,
                     0x70, 0x04, 0x06, 0x05, 0x06, 0x00, 0x00, 0x15, 0x38 );
  data = raw_string( 0x01, 0xbe, 0x00, ( strlen( data ) + 4 ) ) + data;

  soc = open_sock_udp( port );
  if( soc ) {
    send( socket:soc, data:data );
    buf = recv( socket:soc, length:4096 );

    close( soc );
    # Radius-Code: Access-Rejected (3)
    if( buf && ord( buf[0] ) == 3 ) {
      return TRUE;
    }
  }
  return FALSE;
}

# @brief Tries to extract a MAC Address of a passed string. If a MAC Address was found saves it into the KB (Host/mac_address)
#        and registers it as a MAC Host Detail. The function will also verify the syntax of the MAC Address and converts it into
#        the common unioxide syntax "01:23:45:67:89:ab" before saving / registering it.
#
# @param data          The string containing the MAC Address.
# @param desc          The name of the VT which has extracted the MAC Address. This is used when registering the Host Detail.
# @param prefix_string The prefix which is appended in the search pattern (e.g. HWAddress = MAC) to identify the MAC Address.
#
# @note Please note that you should strip the passed string to a minimum before passing it to this function. As an alternative
#       you can also pass a string which should be used in the search pattern (e.g. HWAddress = MAC) to identify the MAC Address.
# @note You need to include "host_details.inc" for @ref register_host_details into your VT.
#
# @return The extracted MAC Address as a string if it was successfully saved / registered, FALSE otherwise and NULL in the
#         case where no data and/or desc parameter was passed.
#
function verify_register_mac_address( data, desc, prefix_string ) {

  local_var data, des, prefix_string;
  local_var mac, final_mac;

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#verify_register_mac_address" );
    return NULL;
  }

  if( ! desc ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#desc#-#verify_register_mac_address" );
    return NULL;
  }

  if( strlen( data ) < 14 )
    return FALSE;

  # unixoide (e.g. ifconfig) output is:
  # 01:23:45:67:89:ab
  #
  # Examples from https://en.wikipedia.org/wiki/MAC_address#Notational_conventions:
  # 01-23-45-67-89-AB
  # 01:23:45:67:89:AB
  # 0123.4567.89AB (e.g. Cisco)
  #
  # nb: The regex is done in a more complex way as we want to extract the digits only to be able to
  # easier convert it into the unixoide syntax later.
  if( mac = eregmatch( string:data, pattern:prefix_string + "(([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})|([0-9a-f]{2})([0-9a-f]{2})\.([0-9a-f]{2})([0-9a-f]{2})\.([0-9a-f]{2})([0-9a-f]{2}))", icase:TRUE ) ) {

    # nb: The second regex for the Cisco syntax starts at index 8
    if( ! isnull( mac[8] ) )
      final_mac = mac[8] + ":" + mac[9] + ":" + mac[10] + ":" + mac[11] + ":" + mac[12] + ":" + mac[13];
    else
      final_mac = mac[2] + ":" + mac[3] + ":" + mac[4] + ":" + mac[5] + ":" + mac[6] + ":" + mac[7];

    final_mac = tolower( final_mac );
    register_host_detail( name:"MAC", value:final_mac, desc:desc );
    replace_kb_item( name:"Host/mac_address", value:final_mac );
    return final_mac;
  }
  return FALSE;
}

# @brief Extracts the value of specific TCP option field from a passed IP (v4 + v6) packet.
#
# @param ip     The IPv4 or IPv6 packet to extract the value of the specified
#               TCP options field from.
# @param option The option to extract. Currently supported: 'Timestamp' and 'WScale'
# @param debug  If debugging should be enabled.
#
# @return The extracted value of the specified TCP option field or NULL if no valid IP packet
#         was passed or an unsupported option field was specified.
#
function tcp_extract_option_field( ip, option, debug ) {

  local_var ip, option, debug;
  local_var hl, hlen, tcp, flags, opt, lo, i, n, tsval, tsecr, scount, len;

  if( isnull( ip ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ip#-#tcp_extract_option_field" );
    return NULL;
  }

  if( ! option ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#option#-#tcp_extract_option_field" );
    return NULL;
  }

  if( strlen( ip ) < 20 )
    return NULL;

  if( "timestamp" >!< tolower( option ) && "wscale" >!< tolower( option ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#tcp_extract_option_field: Invalid option passed to 'option' parameter: " + option + ". Currently supported: 'Timestamp' and 'WScale'" );
    return NULL;
  }

  hl = ord( ip[0] );
  hlen = ( hl & 0xF ) * 4;
  tcp = substr( ip, hlen );

  if( debug ) {
    dump( ddata:ip, dtitle:"IP" );
    dump( ddata:tcp, dtitle:"TCP" );
  }

  if( strlen( tcp ) <= 20 )
    return NULL;

  flags = ord( tcp[13] );
  if( ! ( flags & TH_ACK ) )
    return NULL;

  opt = substr( tcp, 20 );
  if( debug ) dump( ddata:opt, dtitle:"TCP options" );

  lo = strlen( opt );

  for( i = 0; i < lo; ) {
    n = ord( opt[i] );

    if( "timestamp" >< tolower( option ) && n == 8 ) { # Timestamp
      tsval = ntohl( n:substr( opt, i + 2, i + 5 ) );
      if( int( tsval ) == NULL )
        return NULL;

      tsecr = ntohl( n:substr( opt, i + 6, i + 9 ) );
      if( debug ) display( "TSVal=", tsval, " TSecr=", tsecr );

      return tsval;
    } else if( "wscale" >< tolower( option ) && n == 3 ) { # Windows Scale (WScale)
      scount = ord( opt[i + 2] ); # nb: i + 1 is the length of the option
      if( ! isnull( scount ) ) {
        if( debug ) display('---[ Extracted WScale Shift count ]---\n\n', scount );
        return scount;
      }
    } else if( n == 1 ) { # NOP
      i++;
    } else {
      len = ord( opt[i + 1] );
      if( len == 0 )
        break;
      i += len;
    }
  }
  return NULL;
}

# @brief Gets the "raw" EtherType protocol value for a given protocol.
#
# @param proto The (mandatory) EtherType protocol name to return the value for.
#              Currently supported: ipv4, ipv6
#
# @return The protocol value for a given protocol as an integer or NULL if the mandatory 'proto'
#         parameter was missing or contains an unsupported protocol name.

function get_ethertype_proto_value( proto ) {

  local_var proto;

  if( ! proto ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#get_ethertype_proto_value" );
    return NULL;
  }

  proto = tolower( proto );

  if( proto != "ipv4" && proto != "ipv6" ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_ethertype_proto_value: Invalid protocol passed to 'proto' parameter: " + proto + ". Currently supported: 'ipv4' and 'ipv6'" );
    return NULL;
  }

  # nb: See https://en.wikipedia.org/wiki/EtherType#Values for a full list
  if( proto == "ipv4" )
    return 0x0800;
  else if( proto == "ipv6" )
    return 0x86dd;

  return NULL;
}
