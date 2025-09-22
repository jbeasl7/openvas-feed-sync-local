# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

valid_snmpv3_errors = make_list( "Unknown user name",
                                 "Unsupported security level",
                                 "Generic error",
                                 "Session abort failure",
                                 "Unknown security model in message",
                                 "MIB not initialized",
                                 "Authentication failure (incorrect password, community or key)" );

# From nasl_snmpv3_get_action() of:
# https://github.com/greenbone/openvas-scanner/blob/v22.7.2/nasl/nasl_snmp.c#L761-L799
invalid_snmpv3_creds_errors = make_list( "Missing function argument",
                                         "Invalid port value",
                                         "Invalid protocol value",
                                         "Missing privproto or privpass",
                                         "authproto should be md5 or sha1",
                                         "privproto should be des or aes",
                                         # Those two are from snmpv3_get() of:
                                         # https://github.com/greenbone/openvas-scanner/blob/v22.7.2/nasl/nasl_snmp.c#L303-L317
                                         "DES not supported in this net-snmp version",
                                         # nb:
                                         # - If either snmpv3_password and/or snmpv3_privpass is too
                                         #   short (USM_LENGTH_P_MIN which is usually 8)
                                         # - In this case we get a message like e.g. the following
                                         #   from the snmp libs:
                                         #   Error: passphrase chosen is below the length requirements of the USM (min=8).
                                         "generate_Ku: Error" );

global_var snmp_error, v3_creds, valid_snmpv3_errors, invalid_snmpv3_creds_errors, last_snmp_error, _snmp_func_debug;
_snmp_func_debug = FALSE;

function snmp_check_v1( port, community ) {

  local_var port, community;
  local_var oid, protocol, ret;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_check_v1" );
    return;
  }

  if( ! community ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#community#-#snmp_check_v1" );
    return;
  }

  oid = "1.3.6.1.2.1.1.1.0";
  protocol = "udp";

  ret = snmpv1_get( port:port, oid:oid, protocol:protocol, community:community );
  if( ret[0] < 0 ) return;

  if( ret[0] == 0 && ! isnull( ret[1] ) ) return TRUE;

  return;
}

function snmp_check_v2( port, community ) {

  local_var port, community;
  local_var oid, protocol, ret;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_check_v2" );
    return;
  }

  if( ! community ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#community#-#snmp_check_v2" );
    return;
  }

  oid = "1.3.6.1.2.1.1.1.0";
  protocol = "udp";

  ret = snmpv2c_get( port:port, oid:oid, protocol:protocol, community:community );
  if( int( ret[0] ) < 0 ) return;

  if( ret[0] == 0 && ! isnull( ret[1] ) ) return TRUE;

  return;
}

function snmp_check_v3( port ) {

  # nb: v3_creds and snmp_error are global vars
  local_var port;
  local_var oid, protocol, vt_strings, snmpv3_username, snmpv3_password;
  local_var snmpv3_authalgo, snmpv3_privpass, snmpv3_privalgo, ret;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_check_v3" );
    return;
  }

  oid = "1.3.6.1.2.1.1.1.0";
  protocol = "udp";

  snmpv3_username = get_kb_item( "SNMP/v3/username" );
  if( ! snmpv3_username || ( strlen( snmpv3_username ) == 0 ) ) {
    # Set some credentials to test for SNMPv3
    vt_strings = get_vt_strings();
    snmpv3_username = vt_strings["lowercase"];
    snmpv3_authalgo = "md5";
    snmpv3_privalgo = "des";

    # nb: See above for the reason for the length check in these two
    snmpv3_password = vt_strings["lowercase"];
    if( strlen( snmpv3_password ) < 8 )
      snmpv3_password = vt_strings["lowercase_rand"];

    snmpv3_privpass = vt_strings["lowercase"];
    if( strlen( snmpv3_privpass ) < 8 )
      snmpv3_privpass = vt_strings["lowercase_rand"];

  } else {
    snmpv3_password = get_kb_item( "SNMP/v3/password" );
    snmpv3_authalgo = get_kb_item( "SNMP/v3/auth_algorithm" );
    if( ! snmpv3_privpass = get_kb_item( "SNMP/v3/privacy_password" ) )
      snmpv3_privalgo = NULL;
    else
      snmpv3_privalgo = get_kb_item( "SNMP/v3/privacy_algorithm" );

    v3_creds = TRUE;
  }

  ret = snmpv3_get( port:port, protocol:protocol, username:snmpv3_username, oid:oid,
                    authpass:snmpv3_password, authproto:snmpv3_authalgo, privpass:snmpv3_privpass,
                    privproto:snmpv3_privalgo );

  if( ret[0] == -1 ) {
    snmp_error = ret[1];
    if( in_array( array:valid_snmpv3_errors, search:snmp_error ) )
      return 2;
    else
      return;
  }

  if( ret[0] == 0 && ! isnull( ret[1] ) )
    return 1;

  if( ret[0] == -2 )
    snmp_error = ret[1];

  return;
}

function snmp_get( port, oid, version, community ) {

  # nb: last_snmp_error and _snmp_func_debug are global vars
  local_var port, oid, version, community;
  local_var report, v3_username, v3_password, v3_authalgo, v3_privpass, v3_privalgo, ret;

  # The SNMP functions needs this function but the installation might be lacking libsnmp support.
  # Report this back to the caller so we at least know why snmp_get is failing.
  # nb: This functions should be always there since openvas-scanner version 20.08.1 / via:
  # https://github.com/greenbone/openvas-scanner/pull/594
  if( ! defined_func( "snmpv3_get" ) ) {
    report  = "snmp_get: The scanner/libraries are not build with libsnmp support. Advanced SNMP checks will fail.";
    report += " Please rebuild with SNMP support enabled.";
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#" + report );
    return;
  }

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_get" );
    return;
  }

  if( ! oid ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#oid#-#snmp_get" );
    return;
  }

  if( ! version ) version = get_kb_item( "SNMP/" + port + "/preferred_version" );
  if( ! version ) return;

  if( version == 3 ) {

    if( get_kb_item( "SNMP/" + port + "/v3/working" ) ) {

      v3_username = get_kb_item( "SNMP/v3/username" );
      v3_password = get_kb_item( "SNMP/v3/password" );
      v3_authalgo = get_kb_item( "SNMP/v3/auth_algorithm" );
      v3_privpass = get_kb_item( "SNMP/v3/privacy_password" );
      v3_privalgo = get_kb_item( "SNMP/v3/privacy_algorithm" );

      if( v3_username && v3_username != "" ) {

        if( ! v3_privpass ) v3_privalgo = NULL;

        ret = snmpv3_get( port:port, protocol:"udp", username:v3_username, oid:oid,
                          authpass:v3_password, authproto:v3_authalgo, privpass:v3_privpass,
                          privproto:v3_privalgo );

        if( ret[0] != 0 || snmp_is_error_message( ret[1] ) ) {
          last_snmp_error = ret[1];
          if( _snmp_func_debug ) display("SNMP debug: Received error in snmpv3_get " + last_snmp_error );
          return;
        }

        if( ret[0] == 0 && ! snmp_is_error_message( ret[1] ) )
          return snmp_clean_ret( ret[1] );
      }
    }
  }

  if( version == 2 ) {

    if( get_kb_item( "SNMP/" + port + "/v2c/working" ) ) {

      if( ! community ) community = snmp_get_community( port:port, version:2 );

      if( community && community != "" ) {

        ret = snmpv2c_get( port:port, oid:oid, protocol:"udp", community:community );

        if( ret[0] != 0 || snmp_is_error_message( ret[1] ) ) {
          last_snmp_error = ret[1];
          if( _snmp_func_debug ) display("SNMP debug: Received error in snmpv2c_get " + last_snmp_error );
          return;
        }

        if( ret[0] == 0 && ! snmp_is_error_message( ret[1] ) )
          return snmp_clean_ret( ret[1] );
      }
    }
  }

  if( version == 1 ) {

    if( get_kb_item( "SNMP/" + port + "/v1/working" ) ) {

      if( ! community ) community = snmp_get_community( port:port, version:1 );

      if( community && community != "" ) {

        ret = snmpv1_get( port:port, oid:oid, protocol:"udp", community:community );

        if( ret[0] != 0 || snmp_is_error_message( ret[1] ) ) {
          last_snmp_error = ret[1];
          if( _snmp_func_debug ) display("SNMP debug: Received error in snmpv1_get " + last_snmp_error );
          return;
        }
        if( ret[0] == 0 && ! snmp_is_error_message( ret[1] ) )
          return snmp_clean_ret( ret[1] );
      }
    }
  }
  return;
}

function snmp_clean_ret() {

  local_var arg;

  arg = _FCT_ANON_ARGS[0];

  if( ! arg ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#snmp_clean_ret" );
    return;
  }

  return ereg_replace( pattern:'^"(.*)"$', string:arg, replace:"\1" );
}

function snmp_get_community( port, version ) {

  local_var port, version;
  local_var ckey, clist;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_get_community" );
    return;
  }

  if( ! version ) version = get_kb_item( "SNMP/" + port + "/preferred_version" );
  if( ! version ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#snmp_get_community: couldn't determine SNMP version / no SNMP version available" );
    return;
  }

  if( version  == 1 )
    ckey = "SNMP/" + port + "/v1/community";
  else if( version  == 2 )
    ckey = "SNMP/" + port + "/v2c/community";
  else
    return;

  clist = get_kb_list( ckey );

  if( ! clist ) return;

  clist = make_list( clist );

  return clist[ 0 ];
}

function snmp_is_error_message() {

  local_var message, errors, _error;

  message = _FCT_ANON_ARGS[0];

  if( ! message ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#snmp_is_error_message" );
    return;
  }

  errors = make_list( "No Such Object available on this agent at this OID",
                      "No Such Instance" );

  foreach _error( errors ) {
    if( _error >< message )
      return TRUE;
  }
  return;
}

# Get the software and OID from a given pattern
function snmp_get_sw_oid( pattern, port ) {

  local_var pattern, port;
  local_var list, split, i, result;

  if( ! pattern || pattern == "" ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pattern#-#snmp_get_sw_oid" );
    return;
  }

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_get_sw_oid" );
    return;
  }

  if( ! list = get_kb_item( "SNMP/" + port + "/installed_software" ) )
    return;

  split = split( list, sep:"|", keep:FALSE );

  i = 0;
  while( i < max_index( split ) ) {
    if( ereg( pattern:pattern, string:split[i+1] ) ) {
      result = make_array( "oid", split[i],
                           "package", split[i+1] );
      return result;
    }
    i += 2;
  }
}

function snmp_get_port( default ) {

  local_var default;
  local_var port;

  port = get_kb_item( "Services/udp/snmp" );
  if( port )
    default = port;

  if( ! get_udp_port_state( default ) )
    exit( 0 );

  return default;
}

function snmp_get_sysdescr( port ) {

  local_var port;
  local_var sysdescr;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_get_sysdescr" );
    return;
  }

  sysdescr = get_kb_item( "SNMP/" + port + "/sysdescr" );
  if( ! sysdescr )
    return;

  return sysdescr;
}

# @brief Checks via SNMPv1 / SNMPv2c if the SNMP sysDescr of the remote SNMP service is accessible.
#
# @param port      The (required) UDP port of the remote SNMP service.
# @param community The (required) SNMP community to be used.
#
# @return TRUE if it was possible to read the sysDescr, FALSE otherwise and NULL if not all required
#         parameters got passed.
#
function snmp_v12c_sysdescr_accessible( port, community ) {

  local_var port, community;
  local_var size, sz, len, len_hi, len_lo, data, soc, recv;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_v2_sysdescr_accessible" );
    return;
  }

  # nb: Allow an empty community
  if( isnull( community ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#community#-#snmp_v2_sysdescr_accessible" );
    return;
  }

  size = strlen( community );
  sz = size % 256;

  len = 31 + size;
  len_hi = len / 256;
  len_lo = len % 256;

  data = raw_string( 0x30, 0x82, len_hi, len_lo,
                     0x02, 0x01, 0x00, 0x04, sz );

  data += community +
          raw_string( 0xa1,
                      0x18, 0x02, 0x01, 0x01,
                      0x02, 0x01, 0x00, 0x02,
                      0x01, 0x00, 0x30, 0x0D,
                      0x30, 0x82, 0x00, 0x09,
                      0x06, 0x05, 0x2B, 0x06,
                      0x01, 0x02, 0x01, 0x05,
                      0x00 );

  soc = open_sock_udp( port );
  if( ! soc )
    exit( 0 );

  send( socket:soc, data:data );
  recv = recv( socket:soc, length:4096, timeout:3 );
  close( soc );

  if( recv )
    return TRUE;
  else
    return FALSE;
}
