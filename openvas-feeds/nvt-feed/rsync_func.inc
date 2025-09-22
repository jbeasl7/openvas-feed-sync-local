# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# to use this .inc you also have to include:
#
# misc_func.inc
# byte_func.inc

function rsync_connect( port ) {

  local_var port;
  local_var soc, banner, buf;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#rsync_connect" );
    return FALSE;
  }

  soc = open_sock_tcp( port );
  if( ! soc )
    return NULL;

  banner = recv_line( socket:soc, length:8096 );
  if( isnull( banner ) ) {
    close( soc );
    return FALSE;
  }

  send( socket:soc, data:'@RSYNCD: 29.0\n' );

  # Ignore MOTD
  while( TRUE ) {
    buf = recv_line( socket:soc, length:8096 );
    if( ! buf || strstr( buf, '@ERROR' ) )
      break;
  }

  return soc;
}

function rsync_get_module_list( soc ) {

  local_var soc;
  local_var num, line, ret;

  if( ! soc ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#rsync_get_module_list" );
    return FALSE;
  }

  num = 0;
  send( socket:soc, data:'#list\r\n' );
  while( TRUE ) {
    line = recv_line( socket:soc, length:8096, timeout:1 );
    if( ! line || strstr( line, '@RSYNCD' ) )
      break;

   ret[num++] = line;
  }

  return ret;
}

function rsync_authentication_required( module, port ) {

  local_var module, port;
  local_var soc, line;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#rsync_authentication_required" );
    return FALSE;
  }

  soc = rsync_connect( port:port );
  if( ! soc )
    return "unknown";

  send( socket:soc, data:string( module + '\r\n' ) );
  line = recv_line( socket:soc, length:8096 );

  close( soc );

  if( strstr( line, '@RSYNCD: OK' ) ) {
    return 'no';
  } else if( strstr( line, '@RSYNCD: AUTHREQD' ) ) {
    return 'yes';
  } else {
    return 'unknown';
  }
}

function rsync_get_file( soc, module, file ) {

  local_var soc, module, file;
  local_var buf, s, b, ret, plen, pfile, flen, file_end;

  if( isnull( soc ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#rsync_get_file" );
    return FALSE;
  }

  if( isnull( module ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#module#-#rsync_get_file" );
    return FALSE;
  }

  if( isnull( file ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file#-#rsync_get_file" );
    return FALSE;
  }

  set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );

  send( socket:soc, data:module + '\n' );
  buf = recv_line( socket:soc, length:4096 );

  if( "@RSYNCD: OK" >!< buf )
    return FALSE;

  send( socket:soc, data:'--server\n--sender\n-L\n.\n' + module + '/' + file + '\n\n' );
  buf = recv( socket:soc, length:4096 );

  send( socket:soc, data:raw_string( 0, 0, 0, 0 ) );
  buf = recv( socket:soc, length:4096 );

  if( ! buf || buf == "" )
    return FALSE;

  s = hex2raw( s:'0000000000a000000000000000000000000000000000' );

  send( socket:soc, data:s );
  while( b = recv( socket:soc, length:1024 ) )
    ret += b;

  plen  = strlen( s ) + 4;
  pfile = strlen( s ) + 8;

  if( isnull( ret ) || strlen( ret ) < ( pfile + 4 ) )
    return FALSE;

  flen = getdword( blob:ret, pos:plen );
  file_end = pfile + ( flen - 1 );

  if( strlen( ret ) < file_end )
    return FALSE;

  return substr( ret, pfile, file_end );
}

function rsync_get_port( default ) {

  local_var default;
  local_var port;

  if( ! default )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#rsync_get_port" );

  port = get_kb_item( "Services/rsync" );
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
