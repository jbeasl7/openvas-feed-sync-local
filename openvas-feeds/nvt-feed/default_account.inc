# SPDX-FileCopyrightText: 2004 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Private functions
function recv_until( socket, pattern ) {

  local_var socket, pattern;
  local_var i, r, buf;

  i = 0;

  while( TRUE ) {
    i++;
    if( i > 65535 )
      return NULL;

    r = recv( socket:socket, length:1 );
    if( strlen( r ) == 0 )
      return NULL;

    buf += r;
    if( egrep( pattern:pattern, string:buf ) )
      return buf;
  }
}

function _check_telnet( port, login, password ) {

  local_var port, login, password;
  local_var soc, res;

  soc = open_sock_tcp( port );
  if( ! soc )
    return( 0 );

  res = telnet_init( soc );
  res += recv_until( socket:soc, pattern:"ogin:" );
  if( ! res )
    exit( 0 );

  send( socket:soc, data:login + '\r\n' );
  if( isnull( password ) ) {
    send( socket:soc, data:'id\r\n' );
    res = recv_until( socket:soc, pattern:"uid=" );
    close( soc );
    if( res )
      return 1;
    else
      return 0;
  }

  res = recv_until( socket:soc, pattern:"word:" );
  if( isnull( res ) ) {
    close( soc );
    return 0;
  }

  send( socket:soc, data:password + '\r\n' );
  send( socket:soc, data:'id\r\n' );

  res = recv_until( socket:soc, pattern:"uid=" );
  close( soc );
  if( res )
    return 1;
  else
    return 0;
}

# @brief Checks (via SSH first and afterwards via Telnet) if an account is enabled / it is possible
#        to login with the given credentials on the remote host
#
# @param login    The username (as a string) to test
# @param password The password (as a string) to test
#
# @return The port on which the login with the given credentials was possible, NULL otherwise.
#
function check_account( login, password ) {

  local_var login, password;
  local_var _ports, _port, ret, soc, res;

  # nb: Not possible to test at all
  if( ! login ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#login#-#check_account" );
    return;
  }

  if( isnull( password ) )
    password = "";

  # Prefer login through SSH rather than telnet
  _ports = ssh_get_ports( default_port_list:make_list( 22 ) );
  foreach _port( _ports ) {

    if( ssh_dont_try_login( port:_port ) )
      continue;

    # Check if any random user/pass pair is accepted by the SSH service first.
    if( ssh_broken_random_login( port:_port ) )
      continue;

    if( ! soc = open_sock_tcp( _port ) )
      continue;

    ret = ssh_login( socket:soc, login:login, password:password, priv:NULL, passphrase:NULL );
    close( soc );
    if( ret == 0 )
      return _port;
  }

  _port = telnet_get_port( default:23 );

  if( get_kb_item( "telnet/" + _port + "/no_login_banner" ) )
    return;

  res = _check_telnet( port:_port, login:login, password:password );
  if( res )
    return _port;
  else
    return;
}
