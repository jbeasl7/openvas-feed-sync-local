# Copyright (C) 2020 Greenbone Networks GmbH
# Some functions might have been moved from misc_func.inc into this
# include and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# Enables debugging output for a few functions below
global_var _port_service_func_debug;
_port_service_func_debug = 0;

# @brief Returns the info if the given port is marked internally as "fragile".
#
# @param port The port to check if it is marked as fragile.
#
# @return TRUE if the given port is marked as fragile, FALSE otherwise and
#         NULL if no port parameter was given.
#
function port_is_marked_fragile( port ) {

  local_var port;
  local_var fragile_ports, _fragile_port;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#port_is_marked_fragile" );
    return;
  }

  fragile_ports = get_kb_list( "Services/fragile_port" );
  if( ! fragile_ports )
    return;

  foreach _fragile_port( fragile_ports ) {
    if( port == _fragile_port )
      return TRUE;
  }
  return;
}

# @brief Returns all during the portscan phase found / open TCP ports (saved
#        internally in the KB key "TCP/PORTS").
#
# @note This function will fork on multiple open / found ports.
#
# @note Add a dependency to secpod_open_tcp_ports.nasl if you want to use this function.
#
# @return The found TCP port. If no open port was found the function will exit.
#
function tcp_get_all_port() {

  local_var port;

  port = get_kb_item( "TCP/PORTS" );
  if( ! port )
    exit( 0 );

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( port_is_marked_fragile( port:port ) )
    exit( 0 );

  if( ! get_port_state( port ) )
    exit( 0 );

  return port;
}

# @brief Returns all during the portscan phase found / open TCP ports (saved
#        internally in the KB key "TCP/PORTS") as a list.
#
# @note In contrast to @ref tcp_get_all_port this function will not fork and is
#       returning a list instead. This should be used e.g. for Detection-VTs
#       where we want to make sure that we're not getting blocked by the remote
#       service with to many concurrent connections or if a fork for each port
#       is not desired.
#
# @note Add a dependency to secpod_open_tcp_ports.nasl if you want to use this function.
#
# @return A list of all found / open TCP ports or an empty list if no open port was found.
#
function tcp_get_all_ports() {

  local_var ports, kb_ports, _port;

  ports = make_list();
  kb_ports = get_kb_list( "TCP/PORTS" );

  foreach _port( kb_ports ) {

    # Includes e.g. PJL ports which are printing everything
    # sent to them so continue for such a port here
    if( port_is_marked_fragile( port:_port ) )
      continue;

    if( ! get_port_state( _port ) )
      continue;

    ports = make_list( ports, _port );
  }
  return ports;
}

# @brief Returns the first found known to be open TCP port on the remote system. This function
#        replaces the nasl built-in @ref get_host_open_port where you can't control that it
#        doesn't return a "fragile" port.
#
# @param exit_no_found_port If empty / not passed or set to TRUE the function will exit if
#        no open TCP ports were found.
#
# @note Add a dependency to secpod_open_tcp_ports.nasl if you want to use this function.
#
# @return The first found known to be open TCP Port. If none has been found the function will exit
#         or return NULL depending on the passed "exit_no_found_port" parameter.
#
function tcp_get_first_open_port( exit_no_found_port ) {

  local_var exit_no_found_port;
  local_var ports;

  if( isnull( exit_no_found_port ) )
    exit_no_found_port = TRUE;

  ports = tcp_get_all_ports();
  if( isnull( ports[0] ) ) {
    if( exit_no_found_port )
      exit( 0 );
    else
      return NULL;
  } else {
    return ports[0]; # TBD: Bring some randomness into this?
  }
}

# @brief Returns all during the portscan phase found / open UDP ports (saved
#        internally in the KB key "UDP/PORTS").
#
# @note This function will fork on multiple open / found ports.
#
# @note Add a dependency to gb_open_udp_ports.nasl if you want to use this function.
#
# @return The found UDP port. If no open port was found the function will exit.
#
function udp_get_all_port() {

  local_var port;

  port = get_kb_item( "UDP/PORTS" );
  if( ! port )
    exit( 0 );

  if( ! get_udp_port_state( port ) )
    exit( 0 );

  return port;
}

# @brief Returns all during the portscan phase found / open UDP ports (saved
#        internally in the KB key "UDP/PORTS") as a list.
#
# @note In contrast to @ref udp_get_all_port this function will not fork and is
#       returning a list instead. This should be used e.g. for Detection-VTs
#       where we want to make sure that we're not getting blocked by the remote
#       service with to many concurrent connections or if a fork for each port
#       is not desired.
#
# @note Add a dependency to gb_open_udp_ports.nasl if you want to use this function.
#
# @return A list of all found / open UDP ports or an empty list if no open port was found.
#
function udp_get_all_ports() {

  local_var ports, kb_ports, _port;

  ports = make_list();
  kb_ports = get_kb_list( "UDP/PORTS" );

  foreach _port( kb_ports ) {

    if( ! get_udp_port_state( _port ) )
      continue;

    ports = make_list( ports, _port );
  }
  return ports;
}

# @brief Returns all ports of "unknown" services of the remote host which are
#        saved in the KB entry "Services/unknown" as found by the scanner. If no
#        "unknown" services were found on the remote host and no list is passed
#        to the "default_port_list" parameter the function will return an empty
#        list. In the case where the "unscanned_closed" scanner setting is set
#        it will return (if passed) the ports included in the list of the
#        to "no" default_port_list parameter.
#
# @note  In contrast to @ref unknownservice_get_port this function will not fork and is
#        returning a list instead. This should be used e.g. for Detection-VTs
#        where we want to make sure that we're not getting blocked by the remote
#        service with to many concurrent connections or if a fork for each port
#        is not desired.
#
# @param default_port_list The port list to return if "unscanned_closed" is set to "no" and no "unknown" services have been found on the remote host.
# @param nodefault         Don't return an empty list if no "default_port_list" was passed (via the same named parameter), it is still returning an
#                          empty list if no ports matching the passed info were detected.
# @param ipproto           An (optional) IP protocol (e.g. "tcp" or "udp") to evaluate. If this parameter isn't passed it will default to "tcp".
#
# @return The open / found "unknown" ports as a list, if none were found an empty list. In the case of no found ports and
#         "unscanned_closed" is set to "no" a set of default ports or the list passed to the default_port_list parameter.
#
function unknownservice_get_ports( default_port_list, nodefault, ipproto ) {

  local_var default_port_list, nodefault, ipproto;
  local_var __port_list, udp, port_list, _default, _port_list, _port;

  __port_list = make_list();

  if( ! nodefault ) {
    if( ! default_port_list ) {
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default_port_list#-#unknownservice_get_ports" );
      return __port_list;
    }

    if( ! is_array( default_port_list ) ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#unknownservice_get_ports: No list passed in 'default_port_list' parameter" );
      return __port_list;
    }
  }

  # nb: If nodefault is specified above we define an empty default_port_list for some parts of the code below.
  if( ! default_port_list || ! is_array( default_port_list ) )
    default_port_list = __port_list;

  if( ! ipproto )
    ipproto = "tcp";

  if( ipproto == "tcp" ) {
    udp = FALSE;
    port_list = get_kb_list( "Services/unknown" );
  } else {
    if( ipproto == "udp" ) {
      udp = TRUE;
      # nb: We only want to return all unknown UDP ports if this is explicitly enabled within global_settings.nasl
      if( get_kb_item( "global_settings/non-default_udp_service_discovery" ) ) {
        port_list = get_kb_list( "Services/udp/unknown" );
      } else {
        port_list = default_port_list;
      }
    } else {
      udp = FALSE;
      port_list = get_kb_list( "Services/" + ipproto + "/unknown" );
    }
  }

  if( port_list ) {
    _port_list = port_list;
    foreach _default( default_port_list ) {
      if( ! in_array( search:_default, array:port_list, part_match:FALSE ) ) { # The passed default might be already in the Services/unknown list
        _port_list = make_list( _default, _port_list );
      }
    }
  } else {
    _port_list = default_port_list;
  }

  foreach _port( _port_list ) {

    if( ! udp ) {
      # Ignore NetBIOS port as previously done in get_unknown_svc()
      if( _port == 139 )
        continue;

      # Includes e.g. PJL ports which are printing everything
      # sent to them so continue for such a port here
      if( port_is_marked_fragile( port:_port ) )
        continue;
    }

    # Don't check ports passed in the default_port_list. Other detections
    # (like telnet.nasl) might have falsely marked this as known.
    if( ! in_array( search:_port, array:default_port_list, part_match:FALSE ) ) {
      if( ! service_is_unknown( port:_port, ipproto:ipproto ) )
        continue;
    }

    if( ! udp ) {
      if( ! get_port_state( _port ) )
        continue;
    } else {
      if( ! get_udp_port_state( _port ) )
        continue;
    }

    __port_list = make_list( __port_list, _port );
  }

  return __port_list;
}

# @brief Returns all "unknown" ports of the target host which are saved
#        in the KB entry "Services/unknown" found by the scanner. If no
#        ports were found open or no "default" parameter is passed
#        (if "nodefault" isn't set to TRUE) it will exit. In the case
#        where the "unscanned_closed" scanner setting is set to "no"
#        it will return the port passed via the default parameter.
#
# @note This function will fork on multiple open ports.
#
# @param default   The port to return if "unscanned_closed" is set to "no" and no ports have been found open.
# @param nodefault Don't exit if no "default" parameter is passed, it still will exit if no unknown services are detected at all.
# @param ipproto   An (optional) IP protocol (e.g. "tcp" or "udp") to evaluate. If this parameter isn't passed it will default to "tcp".
#
# @return The open / found "unknown" ports or the port passed via the default parameter in the case of no found ports
#         and "unscanned_closed" is set to "no".
#
function unknownservice_get_port( default, nodefault, ipproto ) {

  local_var default, nodefault, ipproto;
  local_var udp, port, _port;

  if( ! nodefault && ! default ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#unknownservice_get_port" );
    exit( 0 );
  }

  if( ! ipproto )
    ipproto = "tcp";

  if( ipproto == "tcp" ) {
    udp = FALSE;
    port = get_kb_item( "Services/unknown" );
  } else {
    if( ipproto == "udp" ) {
      udp = TRUE;
      # nb: We only want to return all unknown UDP ports if this is explicitly enabled within global_settings.nasl
      if( get_kb_item( "global_settings/non-default_udp_service_discovery" ) ) {
        port = get_kb_item( "Services/udp/unknown" );
      } else {
        port = default;
      }
    } else {
      udp = FALSE;
      port = get_kb_item( "Services/" + ipproto + "/unknown" );
    }
  }

  if( port )
    _port = port;
  else
    _port = default;

  if( ! _port )
    exit( 0 );

  if( ! udp ) {
    # Ignore NetBIOS port as previously done in get_unknown_svc()
    if( _port == 139 )
      exit( 0 );

    # Includes e.g. PJL ports which are printing everything
    # sent to them so exit for such a port here
    if( port_is_marked_fragile( port:_port ) )
      exit( 0 );
  }

  # Don't check port passed in default variable. Other detections
  # (like telnet.nasl) might have falsely marked this as known.
  if( _port != default ) {
    if( ! service_is_unknown( port:_port, ipproto:ipproto ) )
      exit( 0 );
  }

  if( ! udp ) {
    if( ! get_port_state( _port ) )
      exit( 0 );
  } else {
    if( ! get_udp_port_state( _port ) )
      exit( 0 );
  }

  return _port;
}

# @brief Gets the first available banner of an "unknown" service from the internal knowledge base
#        (KB) set by e.g. @ref unknown_banner_set or any of the find_service* service detections.
#        If no banner is available the function (if not disabled via the "dontfetch" parameter) will
#        also try to grab a banner from the service.
#
# @param port      The port of the service to get the banner for
# @param ipproto   The IP protocol ("tcp" or "udp"), defaults to "tcp" if not given
# @param dontfetch If set to TRUE the function doesn't try to catch a banner "actively" from the
#                  remote service if none is available in the KB
#
# @return The banner as a raw string (e.g. might include non-printable chars) or NULL if no banner
#         is available
#
function unknown_banner_get( port, ipproto, dontfetch ) {

  local_var port, ipproto, dontfetch;
  local_var kbname, kbnameHex, banner, _p, bannerHex, oids, _oid, soc;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#unknown_banner_get" );
    return;
  }

  if( ! ipproto )
    ipproto = "tcp";

  if( ipproto == "tcp" ) {
    kbname    = strcat( "unknown/banner/", port );
    kbnameHex = strcat( "unknown/bannerHex/", port );
  } else {
    kbname    = strcat( "unknown/banner/", ipproto, "/", port );
    kbnameHex = strcat( "unknown/bannerHex/", ipproto, "/", port );
  }

  banner = get_kb_item( kbnameHex );
  if( banner )
    return hex2raw( s:banner );

  banner = get_kb_item( kbname );
  if( banner )
    return banner;

  banner = get_kb_item( "BannerHex/" + port );
  if( banner )
    return( hex2raw( s:banner ) );

  banner = get_kb_item( "Banner/" + port );
  if( banner )
    return( banner );

  foreach _p( make_list( "spontaneous", "get_http", "help", "xml", "json", "sip", "bin" ) ) {
    banner = get_kb_item( "FindService/" + ipproto + "/" + port + "/" + _p );
    bannerHex = get_kb_item( "FindService/" + ipproto + "/" + port + "/" + _p + "Hex" );
    if( banner || bannerHex ) {
      if( strlen( bannerHex ) > 2 * strlen( banner ) )
        return hex2raw( s:bannerHex );
      else
        return( banner );
    }
  }

  # nb: This is from unknown_banner_set()
  if( ipproto == "tcp" )
    oids = get_kb_list( "unknown/banner/oids/" + port );
  else
    oids = get_kb_list( "unknown/banner/oids/" + ipproto + "/" + port );

  if( oids ) {
    foreach _oid( oids ) {

      if( ipproto == "tcp" ) {
        banner = get_kb_item( "unknown/" + _oid + "/banner/" + port );
        bannerHex = get_kb_item( "unknown/" + _oid + "/bannerHex/" + port );
      } else {
        banner = get_kb_item( "unknown/" + _oid + "/banner/" + ipproto + "/" + port );
        bannerHex = get_kb_item( "unknown/" + _oid + "/bannerHex/" + ipproto + "/" + port );
      }

      if( banner || bannerHex ) {
        if( strlen( bannerHex ) > 2 * strlen( banner ) )
          return hex2raw( s:bannerHex );
        else
          return( banner );
      }
    }
  }

  if( dontfetch )
    return( NULL );

  if( ipproto != "tcp" )
    return( NULL );

  if( ! get_port_state( port ) )
    return( NULL );

  if( ! soc = open_sock_tcp( port ) )
    return( NULL );

  banner = recv( socket:soc, length:2048 );
  close( soc );

  if( banner ) {
    replace_kb_item( name:kbname, value:banner );
    if( '\0' >< banner )
      replace_kb_item( name:kbnameHex, value:hexstr( banner ) );
  }

  return( banner );
}

# @brief Sets a specific banner into the internal knowledge base (KB) for later use via
#        e.g. @ref unknown_banner_get
#
# @param port          The port of the service to set the banner for
# @param banner        The banner to set for the service
# @param ipproto       The IP protocol ("tcp" or "udp"), defaults to "tcp" if not given
# @param set_oid_based If set to TRUE the KB key will be set based on the OID of the calling script
#
# @return NULL
#
function unknown_banner_set( port, banner, ipproto, set_oid_based ) {

  local_var port, banner, ipproto, set_oid_based;
  local_var oid, kbname;

  oid = get_script_oid();

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#port#-#unknown_banner_set" );
    return;
  }

  if( ! banner ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#banner#-#unknown_banner_set" );
    return;
  }

  if( ! ipproto )
    ipproto = "tcp";

  # Can be / is used later in e.g. unknown_banner_get() or unknown_banner_report().
  if( set_oid_based ) {
    if( ipproto == "tcp" )
      set_kb_item( name:"unknown/banner/oids/" + port, value:oid );
    else
      set_kb_item( name:"unknown/banner/oids/" + ipproto + "/" + port, value:oid );
  }

  if( ipproto == "tcp" ) {
    if( set_oid_based )
      kbname = string( "unknown/", oid, "/banner/", port );
    else
      kbname = string( "unknown/banner/", port );
  } else {
    if( set_oid_based )
      kbname = strcat( "unknown/", oid, "/banner/", ipproto, "/", port );
    else
      kbname = strcat( "unknown/banner/", ipproto, "/", port );
  }
  set_kb_item( name:kbname, value:banner );

  if( '\0' >< banner ) {
    if( ipproto == "tcp" ) {
      if( set_oid_based )
        kbname = string( "unknown/", oid, "/bannerHex/", port );
      else
        kbname = string( "unknown/bannerHex/", port );
    } else {
      if( set_oid_based )
        kbname = strcat( "unknown/", oid, "/bannerHex/", ipproto, "/", port );
      else
        kbname = strcat( "unknown/bannerHex/", ipproto, "/", port );
    }
    set_kb_item( name:kbname, value:hexstr( banner ) );
  }

  return;
}

# @brief Reports an unknown banner saved in the KB.
#
# @param port    The port of the service to get the banner for.
# @param ipproto The IP protocol ("tcp" or "udp"), defaults to "tcp" if not given.
#
# @return A list with the following content in the list index:
#         [0] The method used to identify the service (e.g spontaneousHex)
#         [1] The found banner. Note that a "Hex" included in the method name means
#             that the banner is returned as a Hex string.
#
#         or NULL if no port parameter was given or no banner was found.
#
function unknown_banner_report( port, ipproto ) {

  local_var port, ipproto;
  local_var _method, banner, oids, _oid, bannerHex;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#unknown_banner_report" );
    return NULL;
  }

  if( ! ipproto )
    ipproto = "tcp";

  foreach _method( make_list( "spontaneousHex", "spontaneous", "get_httpHex", "get_http", "helpHex", "help", "xmlHex", "xml", "jsonHex", "json", "sipHex", "sip", "binHex", "bin" ) ) {
    banner = get_kb_item( "FindService/" + ipproto + "/" + port + "/" + _method );
    # Later evaluated methods in the foreach loop might have more data so only return here when
    # having enough data...
    if( banner && strlen( banner ) >= 3 ) {
      return( make_list( _method, banner ) );
    }
  }

  if( ipproto == "tcp" ) {
    # nb: Those are coming from / are set by nasl_builtin_find_service.c
    banner = get_kb_item( "unknown/bannerHex/" + port );
    if( banner )
      return( make_list( "'unknown/bannerHex/' KB entry", banner ) );

    banner = get_kb_item( "unknown/banner/" + port );
    if( banner )
      return( make_list( "'unknown/banner/' KB entry", banner ) );
  } else {
    banner = get_kb_item( "unknown/bannerHex/" + ipproto + "/" + port );
    if( banner )
      return( make_list( "'unknown/bannerHex/" + ipproto + "/' KB entry", banner ) );

    banner = get_kb_item( "unknown/banner/" + ipproto + "/" + port );
    if( banner )
      return( make_list( "'unknown/banner/" + ipproto + "/' KB entry", banner ) );
  }

  banner = get_kb_item( "BannerHex/" + port );
  if( banner )
    return( make_list( "'BannerHex/' KB entry", banner ) );

  banner = get_kb_item( "Banner/" + port );
  if( banner )
    return( make_list( "'Banner/' KB entry", banner ) );

  # nb: This is from unknown_banner_set()
  if( ipproto == "tcp" )
    oids = get_kb_list( "unknown/banner/oids/" + port );
  else
    oids = get_kb_list( "unknown/banner/oids/" + ipproto + "/" + port );

  if( oids ) {
    foreach _oid( oids ) {

      if( ipproto == "tcp" ) {
        banner = get_kb_item( "unknown/" + _oid + "/banner/" + port );
        bannerHex = get_kb_item( "unknown/" + _oid + "/bannerHex/" + port );
      } else {
        banner = get_kb_item( "unknown/" + _oid + "/banner/" + ipproto + "/" + port );
        bannerHex = get_kb_item( "unknown/" + _oid + "/bannerHex/" + ipproto + "/" + port );
      }

      # Later evaluated OID results in the foreach loop might have more data so only return here
      # when having enough data...
      if( bannerHex && strlen( bannerHex ) >= 3 )
        return( make_list( "Response to a query of the VT with the OID '" + _oid + "'", bannerHex ) );

      if( banner && strlen( banner ) >= 3 )
        return( make_list( "Response to a query of the VT with the OID '" + _oid + "'", banner ) );
    }
  }
}

# @brief Verifies if the service on the remote host at the specified port is registered with the specified proto.
#
# @param port    The port to check.
# @param ipproto The IP protocol (optional) to check, defaults to "tcp".
# @param proto   A (mandatory) service protocol (e.g. "www" for HTTP were Services/www is evaluated).
#
# @note This function does not fork.
#
# @return TRUE if the service is registered with the specified proto, FALSE otherwise and NULL if no port or proto parameter was passed.
#
function service_verify( port, ipproto, proto ) {

  local_var port, ipproto, proto;
  local_var known, _known;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#verify_service" );
    return NULL;
  }

  if( ! proto ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#verify_service" );
    return NULL;
  }

  if( ! ipproto )
    ipproto = "tcp";

  known = get_kb_list( "Known/" + ipproto + "/" + port );
  if( ! known )
    return FALSE;

  foreach _known( known ) {
    if( _known && _known == proto ) {
      return TRUE;
    }
  }
  return FALSE;
}

# @brief Returns all ports matching the specified IP and service protocol passed via the "ipproto" and "proto" parameters. The function will evaluate
#        the following KB keys for this information:
#
#        "Services/proto" or "Services/ipproto/proto" and "Known/ipproto/default"
#
#        If no ports were found for the specified IP and service protocol or no "default" parameter is passed (if "nodefault" isn't set to TRUE)
#        it will exit. In the case where the "unscanned_closed/unscanned_closed_udp" scanner setting is set to "no" it will return the port passed
#        via the "default" parameter.
#
# @param default             The port to return if "unscanned_closed" is set to "no" and no ports have been found for the specified IP and service protocol.
# @param nodefault           Don't exit if no "default" parameter is passed, it is still exiting if no ports matching the passed info were detected.
# @param ipproto             An (optional) IP protocol (e.g. "tcp" or "udp") to evaluate. If this parameter isn't passed it will default to "tcp".
# @param proto               A (mandatory) service protocol (e.g. "www" for HTTP were Services/www is evaluated).
# @param ignore_unscanned    Returns the ports even if they were "unscanned" previously.
#
# @note This function may fork if multiple ports are found open for the same service.
#
# @return The open / found ports matching the specific IP and service protocol or the port passed via the default parameter
#         in the case of no found ports and "unscanned_closed/unscanned_closed_udp" is set to "no".
#
function service_get_port( default, nodefault, ipproto, proto, ignore_unscanned ) {

  local_var default, nodefault, ipproto, proto, ignore_unscanned;
  local_var key, port;

  if( ! proto ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#service_get_port" );
    exit( 0 );
  }

  if( ! default && ! nodefault ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#service_get_port" );
    exit( 0 );
  }

  if( ! ipproto )
    ipproto = "tcp";

  if( ipproto == "tcp" )
    key = strcat( "Services/", proto );
  else
    key = strcat( "Services/", ipproto, "/", proto );

  port = get_kb_item( key );
  if( port )
    return port;

  # nb: If this is the case we haven't found an open port, default wasn't passed
  # and nodefault was set to TRUE. We can't continue in this case.
  if( ! default )
    exit( 0 );

  port = get_kb_item( "Known/" + ipproto + "/" + default );
  if( port == proto )
    return default;

  if( ipproto == "tcp" && ( get_tcp_port_state( default ) || ignore_unscanned ) ) {

    # Includes e.g. PJL ports which are printing everything sent to them so exit for such
    # a port here.
    if( port_is_marked_fragile( port:default ) )
      exit( 0 );

    return default;
  }

  if( ipproto == "udp" && ( get_udp_port_state( default ) || ignore_unscanned ) )
    return default;

  exit( 0 );
}

# @brief Returns all ports matching the specific IP and service protocol. The function will evaluate the following KB keys for this information:
#        "Services/proto", "Services/ipproto/proto" and "Known/ipproto/default".
#
# @param default_port_list   The port list to return if "unscanned_closed" is set to "no" and no ports have been found for the specified IP and service protocol.
# @param ipproto             An (optional) IP protocol (e.g. "tcp" or "udp") to evaluate. If this parameter isn't passed it will default to "tcp".
# @param proto               A (mandatory) service protocol (e.g. "www" for HTTP were Services/www is evaluated).
# @param ignore_unscanned    Returns the ports even if they were "unscanned" previously.
#
# @note  In contrast to @ref service_get_ports this function will not fork and return a list instead. This should be used e.g. for
#        Detection-VTs where we want to make sure that we're not getting blocked by the remote service with to many concurrent connections.
#
# @return A list containing the open / found ports matching the specific IP and service protocol, if none were found an empty list. In the case of
#         no found ports and "unscanned_closed/unscanned_closed_udp" is set to "no" the list passed to the default_port_list parameter is returned.
#
function service_get_ports( default_port_list, ipproto, proto, ignore_unscanned ) {

  local_var default_port_list, ipproto, proto, ignore_unscanned;
  local_var port_list, num_ports, key, ports, _port, _default;

  port_list = make_list();

  if( ! proto ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#service_get_ports" );
    return port_list;
  }

  num_ports = 0;

  if( ! ipproto )
    ipproto = "tcp";

  if( ipproto == "tcp" )
    key = strcat( "Services/", proto );
  else
    key = strcat( "Services/", ipproto, "/", proto );

  ports = get_kb_list( key );
  if( ports && typeof( ports ) == "array" ) {
    foreach _port( ports ) {
      num_ports++;
      port_list = make_list( port_list, _port );
    }
  }

  if( num_ports > 0 )
    return port_list;

  # nb: If this is the case we haven't found an open port and the default_port_list
  # parameter wasn't passed. We can't continue in this case.
  if( ! default_port_list || typeof( default_port_list ) != "array" )
    return port_list;

  foreach _default( default_port_list ) {
    ports = get_kb_list( "Known/" + ipproto + "/" + _default );
    if( ports && typeof( ports ) == "array" ) {
      foreach _port( keys( ports ) ) {
        if( ports[_port] == proto ) {
          num_ports++;
          port_list = make_list( port_list, _default );
        }
      }
    }
  }

  if( num_ports > 0 )
    return port_list;

  foreach _default( default_port_list ) {

    if( ipproto == "tcp" && ( get_tcp_port_state( _default ) || ignore_unscanned ) ) {

      # Includes e.g. PJL ports which are printing everything sent to them so continue
      # for such a port here.
      if( port_is_marked_fragile( port:_default ) )
        continue;

      port_list = make_list( port_list, _default );
    }

    if( ipproto == "udp" && ( get_udp_port_state( _default ) || ignore_unscanned ) )
      port_list = make_list( port_list, _default );
  }

  return port_list;
}

function service_report( port, svc, banner, message ) {

  local_var port, svc, banner, message;
  local_var name, a, report;

  if( ! port )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#service_report" );

  if( ! svc )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#svc#-#service_report" );

  svc = tolower( svc );
  if( banner && strlen( banner ) > 0 )
    set_kb_item( name:svc + "/banner/" + port, value:banner );

  if( svc == "www" )
    name = "web server";
  else if( svc == "proxy" )
    name = "web proxy";
  else if( svc == "hylafax-ftp" || svc == "hylafax" )
    name = "HylaFAX server";
  else if( svc == "agobot.fo" )
    name = "Agobot.fo backdoor";
  else if( svc == "unknown_irc_bot" )
    name = "IRC bot";
  else if( svc == "auth" )
    name = "identd";
  else if( svc == "workgroupshare" )
    name = "WorkgroupShare Server";
  else
    name = toupper( svc ) + " server";

  a = tolower( name[0] );
  if( a == "a" || a == "e" || a == "i" || a == "o" )
    a = "An ";
  else
    a = "A ";

  report = a + name + " is running on this port.";

  if( ! message )
    message = report;

  service_register( port:port, proto:svc, message:message );
  log_message( port:port, data:report );
}

# @brief Register a service in the internal knowledgebase with the given info.
#
# @param port    The (mandatory) port of the service to register.
# @param proto   A (mandatory) service protocol (e.g. "www" for HTTP) to register.
# @param ipproto An (optional) IP protocol (e.g. "tcp" or "udp") to register the service for.
#                If this parameter isn't passed it will default to "tcp".
# @param message An (optional) message which is assigned to the Host Detail related to the
#                registered service.
#
# @return NULL
#
function service_register( port, proto, ipproto, message ) {

  local_var port, proto, ipproto, message;
  local_var key;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#service_register" );
    return;
  }

  if( ! proto ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#service_register" );
    return;
  }

  if( ! ipproto )
    ipproto = "tcp";

  if( ! service_is_unknown( port:port, ipproto:ipproto ) ) {
    if( _port_service_func_debug ) display(get_host_ip(), ": service is already known on port ", ipproto, ":", port, "\n");
    #return(0);
  }

  if( ipproto != "unknown" ) {

    key = strcat( "Known/", ipproto, "/", port );
    replace_kb_item( name:key, value:proto );
    if( ipproto == "tcp" )
      key = strcat( "Services/", proto );
    else
      key = strcat( "Services/", ipproto, "/", proto );
    set_kb_item( name:key, value:port );

    service_register_as_host_detail( port:port, proto:ipproto, service:proto, message:message );
  }
  if( _port_service_func_debug ) display(get_host_ip(), ": service_register: port=", port, ", proto=", proto, "\n");
  return;
}

# @brief Internal function to be called by @service_register only
#
function service_register_as_host_detail( port, proto, service, message ) {

  local_var port, proto, service, message;
  local_var hd;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#service_register_as_host_detail" );
    return;
  }

  if( ! service ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#service#-#service_register_as_host_detail" );
    return;
  }

  if( ! proto )
    proto = "tcp";

  # "623, udp, ipmi,'An IPMI service is running at this port. Supported IPMI version(s): v1.5, v2.0\n'"
  hd = port + "," + proto + "," + service;

  if( message )
    hd += "," + message;

  register_host_detail( name:"Services", value:hd, desc:"Service detection (" + get_script_oid() + ")" );

  return;
}

# @brief Checks if the service on the remote host at the specified port is unknown / not registered in the KB.
#
# @param port    The port to check.
# @param ipproto The IP protocol (optional) to check, defaults to "tcp".
#
# @note This function does not fork.
#
# @return TRUE if the service is unknown, FALSE otherwise and NULL if no port parameter was passed.
#
function service_is_unknown( port, ipproto ) {

  local_var port, ipproto;
  local_var known, _known;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#service_is_unknown" );
    return NULL;
  }

  if( ! ipproto )
    ipproto = "tcp";

  known = get_kb_list( "Known/" + ipproto + "/" + port );
  if( ! known )
    return TRUE;

  foreach _known( known ) {
    if( _known && _known != "unknown" ) {
      return FALSE;
    }
  }
  return TRUE;
}

# @brief Checks if the service on the remote host at the specified port is known / registered in the KB.
#
# @param port    The port to check.
# @param ipproto The IP protocol (optional) to check, defaults to "tcp".
#
# @note This function does not fork.
#
# @return TRUE if the service is known, FALSE otherwise and NULL if no port parameter was passed.
#
function service_is_known( port, ipproto ) {

  local_var port, ipproto;
  local_var known, _known;

  if( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#service_is_known" );
    return NULL;
  }

  if( ! ipproto )
    ipproto = "tcp";

  known = get_kb_list( "Known/" + ipproto + "/" + port );
  if( ! known )
    return FALSE;

  foreach _known( known ) {
    if( _known && _known != "unknown" ) {
      return TRUE;
    }
  }
  return FALSE;
}
