# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

function ldap_alive( port ) {

  local_var port;
  local_var req, soc, buf, response;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ldap_alive" );
    return;
  }

  req = raw_string( 0x30, 0x84, 0x00, 0x00, 0x00, 0x59, 0x02, 0x01, 0x05, 0x63, 0x84, 0x00,
                    0x00, 0x00, 0x50, 0x04, 0x13, 0x64, 0x63, 0x3d, 0x6f, 0x70, 0x65, 0x6e,
                    0x76, 0x61, 0x73, 0x64, 0x63, 0x2c, 0x64, 0x63, 0x3d, 0x6e, 0x65, 0x74,
                    0x0a, 0x01, 0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
                    0x01, 0x01, 0x00, 0xa3, 0x84, 0x00, 0x00, 0x00, 0x13, 0x04, 0x0b, 0x6f,
                    0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x04, 0x04,
                    0x75, 0x73, 0x65, 0x72, 0x30, 0x84, 0x00, 0x00, 0x00, 0x0d, 0x04, 0x0b,
                    0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65 );

  soc = open_sock_tcp( port );
  if( ! soc )
    return FALSE;

  send( socket:soc, data:req );
  buf = recv( socket:soc, length:32 );
  close( soc );

  if( isnull( buf ) )
    return FALSE;

  # TODO: This is still quite fragile...
  # We shouldn't do a service detection just on the base of one single response char
  if( strlen( buf ) > 5 ) {
    response = hexstr( buf[0] );
    if( response =~ "^30$" )
      return TRUE;
  }
  return FALSE;
}

function ldap_starttls_supported( port ) {

  local_var port;
  local_var soc, req, recv, er_length, extended_response;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ldap_starttls_supported" );
    return;
  }

  soc = open_sock_tcp( port );
  if( ! soc )
    return FALSE;

  req = raw_string( 0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80,
                    0x16, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31,
                    0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36,
                    0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37 );

  send( socket:soc, data:req );
  recv = recv( socket:soc, length:1024 );
  close( soc );

  if( ! recv || isnull( recv ) || strlen( recv ) < 6 )
    return FALSE;

  if( ord( recv[0] ) == 48 ) {
    ber_size_info = get_ber_size( buf:recv, offset:6 );
    er_length = ber_size_info[0];
    extended_response = substr( recv, strlen( recv ) - er_length, strlen( recv ) );

    if( extended_response && strlen( extended_response ) > 2 && ord( extended_response[2] ) == 0 ) {
      return TRUE;
    }
  }
}

function get_ber_size( buf, offset ) {

  local_var buf, offset;
  local_var lm_length, length_length, i, ret;

  lm_length = ord( buf[offset] );
  offset++;

  if( lm_length > 128 ) {
    # undetermined length message
    length_length = lm_length - 128;
    lm_length = 0;
    for( i = 0; i < length_length; i++ ) {
      lm_length = ( lm_length << 8 ) | ord( buf[offset++] );
    }
  }

  ret = make_list( lm_length, offset );
  return ret;
}

# @brief Checks if a remote LDAP server has LDAPv3 enabled (accepting the LDAPv3 bind). The result is
#        cached within the KB to avoid re-connection to the server if it is already known if the
#        server is/isn't supporting LDAPv3.
#
# @param port The port of the remote LDAP server to connect to.
#
# @return TRUE if the LDAP server has LDAPv3 enabled, FALSE otherwise.
#
function ldap_is_v3( port ) {

  local_var port;
  local_var is_ldapv3, soc, req, buf, lm_length, messageId_length, offset, bindResponse_length, resultCode_length, resultCode, i;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ldap_is_v3" );
    return;
  }

  is_ldapv3 = get_kb_item( "ldap/" + port + "/is_ldapv3" );
  if( is_ldapv3 == "yes" )
    return TRUE;
  else if( is_ldapv3 == "no" )
    return FALSE;

  soc = open_sock_tcp( port );
  if( ! soc )
    return FALSE;

  req = raw_string( 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07,
                    0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 ); # v3 bind
  send( socket:soc, data:req );

  buf = recv( socket:soc, length:128 );
  close( soc );
  if( ! buf )
    return FALSE;

  # decode ldapMessage length (encoded as BER)
  offset = 0;
  if( ord( buf[offset++] ) != 48 ) {
    replace_kb_item( name:"ldap/" + port + "/is_ldapv3", value:"no" );
    return FALSE; # (0x30)
  }

  ber_size_info = get_ber_size( buf:buf, offset:offset );
  lm_length = ber_size_info[0];
  offset = ber_size_info[1];
  if( strlen( buf ) < lm_length + offset )
    return FALSE; # whoops, we have not enough data (should never happen since bindResponse is a short message)

  # we are not at offset = message id, we skip it
  if( ord( buf[offset++] ) != 2 ) {
    replace_kb_item( name:"ldap/" + port + "/is_ldapv3", value:"no" );
    return FALSE; # messageId is an INT
  }

  ber_size_info = get_ber_size( buf:buf, offset:offset );
  messageId_length = ber_size_info[0];
  offset = ber_size_info[1];
  offset += messageId_length;

  # now enter the bindResponse
  if( ord( buf[offset++] ) != 97 ) {
    replace_kb_item( name:"ldap/" + port + "/is_ldapv3", value:"no" );
    return FALSE; # (0x61)
  }

  ber_size_info = get_ber_size( buf:buf, offset:offset );
  bindResponse_length = ber_size_info[0];
  offset = ber_size_info[1];

  # now dig into response code
  if( ord( buf[offset++] ) != 10 ) {
    replace_kb_item( name:"ldap/" + port + "/is_ldapv3", value:"no" );
    return FALSE; # (0x0A)
  }

  ber_size_info = get_ber_size( buf:buf, offset:offset );
  resultCode_length = ber_size_info[0];
  offset = ber_size_info[1];

  resultCode = 0;
  for( i = 0; i < resultCode_length; i++ ) {
    resultCode = ( resultCode << 8 ) | ord( buf[offset++] );
  }

  if( resultCode == 0 ) {
    replace_kb_item( name:"ldap/" + port + "/is_ldapv3", value:"yes" );
    return TRUE; # server has accepted the v3 bind
  } else {
    replace_kb_item( name:"ldap/" + port + "/is_ldapv3", value:"no" );
    return FALSE;
  }
}

function ldap_get_port( default ) {

  local_var default;
  local_var port;

  if( ! default )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#ldap_get_port" );

  port = get_kb_item( "Services/ldap" );
  if( port )
    default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( port_is_marked_fragile( port:default ) )
     exit( 0 );

  if( ! get_port_state( default ) )
    exit( 0 );

  return default;
}

function ldap_int( number ) {

  local_var number;
  local_var x, len;

  len = FALSE;
  while( x < strlen( number ) ) {
    len = len * 256 + ord( number[ x ] );
    x++;
  }
  return len;
}

function ldap_send_recv( req, sock ) {

  local_var req, sock;
  local_var res, len, next_len;

  if( ! req || ! sock )
    return;

  send( socket:sock, data:req );

  res = recv( socket:sock, length:2 );

  if( strlen( res ) < 2 )
    return;

  if( res[0] != '\x30' )
    return;

  len = ord( res[1] );

  if( len >= 128 ) {
    len -= 128;
    next_len = recv( socket:sock, length:len );

    if( strlen( next_len ) < len )
      return;

    len = ldap_int( number:next_len );

    if( ! len || len < 1 )
      return;
  }

  return( recv( socket:sock, length:len ) );
}
