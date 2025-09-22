# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Used in get_app_port/get_app_location to return a default
# location if none was previously detected and optimize_test
# is set to "no".
global_var optimize_test_enabled;
optimize_test_enabled = get_preference( "optimize_test" );

# Those are for debugging purposes (see get_app_version() and get_app_location())
global_var _get_app_version_used, _get_app_location_used;

##
# This script exports a function to store host information in a structured
# way.
#
# <host>
#   <detail>
#     <name>OS</name>
#     <value>Debian</value>
#     <source>
#       <type>nvt</type>
#       <name>1.2.3.4.5.6</name>
#       <description>VT description</description>
#     </source>
#   </detail>
# </host>
# <host>
#   <detail>
#     <name>OS</name>
#     <value>cpe:/o:debian_linux:debian:5.0</value>
#     <source>
#       <type>nvt</type>
#       <nvt>1.2.3.4</nvt>
#       <description>another VT description</description>
#     </source>
#   </detail>
# </host>
#
# For this example, we would use these KB entries:
# ------------------------------------------------
#
# HostDetails                     => "OS"
# HostDetails/NVT                 => "1.2.3.4.5.6"
# --
# HostDetails/NVT/1.2.3.4.5.6     => "VT Description"
# HostDetails/NVT/1.2.3.4.5.6/OS  => "Debian"
# --
# HostDetails                     => "OS"
# HostDetails/NVT                 => "1.2.3.4"
# --
# HostDetails/NVT/1.2.3.4         => "another VT description"
# HostDetails/NVT/1.2.3.4/OS      => "cpe:/o:debian_linux:debian:5.0"
##

# @brief Register the specified info as a "HostDetail" into the knowledge base for use by other VTs.
#
# @param name  The name of the HostDetail to register.
# @param value The value to assign to the specified HostDetail name.
# @param desc  A text description of the registered HostDetail.
#
# @return NULL
#
function register_host_detail( name, value, desc ) {

  local_var name, value, desc;
  local_var nvt;

  if( ! name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#register_host_detail" );
    return;
  }

  if( ! value )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#value#-#register_host_detail" );

  nvt = get_script_oid();
  if( ! nvt )
    return;

  if( name != "port" ) {
    set_kb_item( name:"HostDetails", value:name );
    set_kb_item( name:"HostDetails/NVT", value:nvt );
    if( ! isnull( desc ) )
      replace_kb_item( name:"HostDetails/NVT/" + nvt, value:desc );
  }

  if( value )
    set_kb_item( name:"HostDetails/NVT/" + nvt + "/" + name, value:value );
}

# @brief Registers a specific product as an "App" HostDetails to the scanner/manager for later
#        use by other VTs and internal functions.
#
# @param cpe              The (mandatory) cpe to assign to the registered product.
# @param location         The (optional) location to assign to the registered product, e.g. 80/tcp or /path/to/folder. Defaults to "/" if none given.
# @param port             The (optional) port to assign to the registered product, e.g. 80 or 443. Defaults to "0" if none given.
# @param proto            The (optional) protocol to assign to the registered product, e.g. "tcp" or "udp". Defaults to "tcp" if none given.
# @param service          The (optional) service to assign to the registered product, e.g. "www", "mysql" or "local". No default is used if none given.
# @param internal_version The (optional) version to assign to the registered product if the version can not be stored within the cpe. No default is used if none given.
#
# @return NULL
#
function register_product( cpe, location, port, proto, service, internal_version ) {

  local_var cpe, location, port, proto, service, internal_version;
  local_var base_cpe, kb_e;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#register_product" );
    return;
  }

  if( ! location ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#location#-#register_product" );
    location = "/";
  }

  register_host_detail( name:"App", value:cpe );
  register_host_detail( name:cpe, value:location );
  if( port )
    register_host_detail( name:"port", value:port );

  # store an entry under the "base" cpe, so we could fork later for each entry under a cpe
  if( ! base_cpe = get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#register_product()#-#" + cpe + "#-#cpe" );
    base_cpe = cpe;
  }

  if( ! proto )
    proto = "tcp";

  if( isnull( port ) )
    port = 0;

  if( service && internal_version )
    kb_e = get_script_oid() + "#-#" + cpe + "#-#" + location + "#-#" + port + "#-#" + proto + "#-#" + service + "#-#" + internal_version;
  else if( service )
    kb_e = get_script_oid() + "#-#" + cpe + "#-#" + location + "#-#" + port + "#-#" + proto + "#-#" + service;
  else if( internal_version )
    kb_e = get_script_oid() + "#-#" + cpe + "#-#" + location + "#-#" + port + "#-#" + proto + "#-##-#" + internal_version;
  else
    kb_e = get_script_oid() + "#-#" + cpe + "#-#" + location + "#-#" + port + "#-#" + proto;

  set_kb_item( name:"get_app/" + base_cpe, value:kb_e );

  if( port == 0 )
    set_kb_item( name:"get_app/ports/" + base_cpe, value:"local" ); # For products identified locally. We currently can't set a value of 0 here.
  else
    set_kb_item( name:"get_app/ports/" + base_cpe, value:port );

  set_kb_item( name:"get_app/protocols/" + base_cpe, value:proto );

  if( service )
    set_kb_item( name:"get_app/services/" + port + "/" + base_cpe, value:service );
}

# @brief Returns a list of HostDetails matching the specified key, e.g. host_details_list( key:"OS" ).
#
# @param key The key to return the matching HostDetails, e.g. "OS" or "App".
#
# @return A list containing the matching HostDetails or NULL if no host details exists.
#
function host_details_list( key ) {
  local_var key;
  return get_kb_list( "HostDetails/NVT/*/" + key );
}

# @brief Register the specified info as a "HostDetail" in a XML format directly to the scanner/manager (as a "Host_Details" proto log_message).
#
# @param name  The name of the HostDetail to register.
# @param value The value to assign to the specified HostDetail name.
# @param nvt   The name of the VT registering the HostDetails.
# @param desc  A text description of the registered HostDetail.
#
# @return NULL
#
function report_host_detail_single( name, value, nvt, desc ) {

  local_var name, value, nvt, desc;
  local_var report;

  if( ! name ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#report_host_detail_single" );
  if( ! value ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#value#-#report_host_detail_single" );
  if( ! nvt ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#nvt#-#report_host_detail_single" );

  report = "";

  report += xml_open_tag( tag:"host" );
  report += xml_open_tag( tag:"detail" );
  report += xml_tagline( tag:"name", value:name );
  report += xml_tagline( tag:"value", value:value );
  report += xml_open_tag( tag:"source" );
  report += xml_tagline( tag:"type", value:"nvt" );
  report += xml_tagline( tag:"name", value:nvt );

  if( ! isnull( desc ) )
    report += xml_tagline( tag:"description", value:desc );
  else
    report += "<description/>";

  report += xml_close_tag( tag:"source" );
  report += xml_close_tag( tag:"detail" );
  report += xml_close_tag( tag:"host" );

  log_message( proto:"Host_Details", data:report );
}

# @brief Iterate over the host details and report them individually. Additionally report best CPE and TXT available concerning the remote OS.
#
# @return NULL
#
function report_host_details() {

  local_var names, nvts, _nvt, desc, _name, details, _item;

  # get the names of the host details we gathered
  names = get_kb_list( "HostDetails" );

  # list of concerned VTs
  nvts = get_kb_list( "HostDetails/NVT" );
  foreach _nvt( nvts ) {

    # description of the current VT
    desc = get_kb_item( "HostDetails/NVT/" + _nvt );

    # iterate over the registered entries...
    foreach _name( names ) {
      details = get_kb_list( "HostDetails/NVT/" + _nvt + "/" + _name );

      # add a section in case the current VT has some value for this entry
      foreach _item( details ) {
        if( ! isnull( _item ) ) {
          report_host_detail_single( name:_name, value:_item, nvt:_nvt, desc:desc );
        }
      }
    }
  }

  # Report best OS entries
  os_report_best_cpe();
  os_report_best_txt();
}

# @brief Returns a list of CPEs containing all the registered entries for applications on the remote host.
#
# @return A list of containing all the registered entries for applications on the remote host, an empty list
#         if no application where registered.
#
function host_details_cpes() {

  local_var res, details_list, _item, item;

  res = make_list();

  # get all the registered entries for applications
  details_list = host_details_list( key:"App" );

  if( ! isnull( details_list ) )
    foreach _item( details_list )
      if( "cpe:/" >< _item )
        res = make_list( res, _item );

  # get the best CPE we have for operating system (if any)
  item = os_get_best_cpe();
  if( ! isnull( item ) )
    res = make_list( res, item );

  return res;
}

# @brief Unused function. TODO: What is the function doing? Do we need to keep it?
#
# @param cpe
# @param loc
#
# @return
#
function get_app( cpe, loc ) {

  local_var cpe, loc;
  local_var host_details, _host_detail, host_values, res, port, location, locations, l;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app" );
    return;
  }

  host_details = get_kb_list( "HostDetails/NVT/*" );
  if( ! host_details )
    return NULL;

  foreach _host_detail( keys( host_details ) ) {

    if( cpe >< _host_detail ) {

      host_values = split( _host_detail, sep:"/", keep:FALSE );

      if( isnull( host_values[2] ) || isnull( host_values[4] ) || "cpe:" >!< host_values[3] )
        return NULL;

      res = make_array();

      res["OID"] = host_values[2];
      res["CPE"] = "cpe:/" + host_values[4];

      port = get_kb_item( "HostDetails/NVT/" + res["OID"] + "/port" ); # nb: this could fork

      if( port )
        res["port"] = port;

      # TODO: This looks broken. Why is the "loc" ignored here and the same (but only the first entry) of
      # a list below is used instead?
      if( loc ) {
        location = get_kb_item( "HostDetails/NVT/" + res["OID"] + "/" + res["CPE"] ); # nb: this could fork
        res["LOCATION"] = location;
      } else {
        locations = get_kb_list( "HostDetails/NVT/" + res["OID"] + "/" + res["CPE"] );
        l = make_list( locations );
        if( max_index( l ) == 1 )
          location = l[0];
      }

      # Store link between scripts.
      register_host_detail( name:"detected_by", value:res["OID"] );
      register_host_detail( name:"detected_at", value:location );

      return res;
    }
  }
  return NULL;
}

# register_product( cpe:"cpe:/a:foo:bar:1.1.0", location:"/foo", port: 80);
# register_product( cpe:"cpe:/a:foo:bar:1.2.0", location:"/bar", port: 80);
# register_product( cpe:"cpe:/a:foo:bar:1.3.0", location:"/foobar", port: 8080);
#                                                                                                                          ,--[1.1.0]
#                                                 ,--[ 80 ] -> get_app_version( cpe:"cpe:/a:foo:bar", port:80 ) -> fork -> |
#                                                 |                                                                        `--[1.2.0]
# get_app_port( cpe:"cpe:/a:foo:bar" ) -> fork -> |
#                                                 `--[8080] -> get_app_version( cpe:"cpe:/a:foo:bar", port:8080 ) -> [1.3.0]
# Without port:
#
#                                                    ,--[1.1.0]
# get_app_version( cpe:"cpe:/a:foo:bar" ) -> fork -> |
#                                                    |--[1.2.0]
#                                                    |
#                                                    `--[1.3.0]
#
#
#                                                                                                                           ,--[/foo]
#                                                 ,--[ 80 ] -> get_app_location( cpe:"cpe:/a:foo:bar", port:80 ) -> fork -> |
#                                                 |                                                                         `--[/bar]
# get_app_port( cpe:"cpe:/a:foo:bar" ) -> fork -> |
#                                                 `--[8080] -> get_app_location( cpe:"cpe:/a:foo:bar", port:8080 ) -> [/foobar]
#
# Without port:
#                                                     ,--[/foo]
# get_app_location( cpe:"cpe:/a:foo:bar" ) -> fork -> |
#                                                     |--[/bar]
#                                                     |
#                                                     `--[/foobar]
#
#
#                                                                                                                                       ,-> array -> ( [version:1.1.0] [location:/foo] )
#                                                 ,--[ 80 ] -> get_app_version_and_location( cpe:"cpe:/a:foo:bar", port:80 ) -> fork -> |
#                                                 |                                                                                     `-> array -> ( [version:1.2.0] [location:bar] )
# get_app_port( cpe:"cpe:/a:foo:bar" ) -> fork -> |
#                                                 `--[8080] -> get_app_version_and_location( cpe:"cpe:/a:foo:bar", port:8080 ) -> array -> ( [version:1.3.0] [location:/foobar] )
# Without port:
#
#                                                                 ,-> array -> ( [version:1.1.0] [location:/foo] )
# get_app_version_and_location( cpe:"cpe:/a:foo:bar" ) -> fork -> |
#                                                                 |-> array -> ( [version:1.2.0] [location:/bar] )
#                                                                 |
#                                                                 `-> array -> ( [version:1.3.0] [location:/foobar] )
#

# @brief Returns the version of an application registered for the remote host within the KB matching the specified data.
#
# @param cpe           The CPE to get the version for.
# @param port          The port of the application to get the version for, e.g. "80".
# @param service       The service of the application to get the version for, e.g. "www", "mysql" or "local".
# @param nofork        If the function shouldn't fork and only return the first registered version (and not all available).
# @param version_regex A regex to restrict the returned version to. E.g. if a version "1.2" was registered but a
#                      regex like "^[0-9]+\.[0-9]+\.[0-9]+" is specified the function won't return the version.
#
# @return A version of the application matching the specified data, NULL in the case no CPE was passed or no matching info was found.
#
# @note *NEVER* use get_app_version() and get_app_location() together in a single VT. If both information is required,
#       use get_app_version_and_location() or get_app_full().
#
function get_app_version( cpe, port, service, nofork, version_regex ) {

  local_var cpe, port, service, nofork, version_regex;

  # To report if get_app_version() and get_app_location() is used together in one single VT
  _get_app_version_used = TRUE;
  if( _get_app_location_used )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version() used together with get_app_location() in one single VT. Please use get_app_version_and_location instead." );

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_version" );
    return;
  }

  # nb: Older variants of this function allowed to pass a string or a list of CPEs via the "cpe" parameter. This was
  # unexpected / broken by design and removed later (also from all known VTs doing this) but we still want to do some
  # additional logging in case one got missed or there are private VTs out there doing the same.
  if( typeof( cpe ) == "array" ) {
    if( ! cpe[0] ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version: List with an empty element passed to the 'cpe' parameter. Please only pass a single CPE in form of a string to this function." );
      return;
    } else {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version: Passing a list of CPEs to the 'cpe' parameter is deprecated / unsupported. Only using the first CPE from this list." );
      cpe = cpe[0];
    }
  }

  return get_app_details( cpe:cpe, type:"version", port:port, service:service, nofork:nofork, version_regex:version_regex );
}

# @brief Returns the highest app version registered in the KB for the specified CPE.
#
# @param cpe  The CPE to use to gather the highest app version for.
# @param port The (optional) port of the application to get highest version for, e.g. "80".
#
# @return The highest version of the application matching the specified CPE, NULL in the case no CPE was passed or no matching info was found.
#
# @note If you use this you need to include revisions-lib.inc.
#
function get_highest_app_version( cpe, port ) {

  local_var cpe, port;
  local_var ad, ret_version, _version;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_highest_app_version" );
    return;
  }

  ad = get_app_details( cpe:cpe, type:"all_versions", port:port );
  if( ! ad )
    return;

  ret_version = FALSE;

  foreach _version( ad ) {
    if( ! ret_version ) {
      ret_version = _version;
      continue;
    }

    # from revisions-lib.inc
    if( revcomp( a:_version, b:ret_version ) == 1 )
      ret_version = _version;
  }
  return ret_version;
}

# @brief Returns the location of an application registered for the remote host within the KB matching the specified data.
#
# @param cpe       The CPE to get the location for.
# @param port      The port of the application to get the location for, e.g. "80".
# @param nofork    If the function shouldn't fork and only return the first registered location (and not all available).
# @param skip_port If set to TRUE allows to get all locations independent from the port.
# @param default   The default location to return in the case "optimize_test" is set to "no" and no location was found
#                  for the given CPE and/or port.
#
# @return A location of the application matching the specified data, NULL in the case no CPE was passed or no matching info was found.
#         The return value is either a list of locations if nofork is set to TRUE or a string containing the list.
#
# @note *NEVER* use get_app_version() and get_app_location() together in a single VT. If both information is required,
#       use get_app_version_and_location() or get_app_full().
#
function get_app_location( cpe, port, nofork, skip_port, default ) {

  local_var cpe, port, nofork, skip_port, default;

  # To report if get_app_version() and get_app_location() is used together in one single VT
  _get_app_location_used = TRUE;
  if( _get_app_version_used )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version() used together with get_app_location() in one single VT. Please use get_app_version_and_location instead." );

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_location" );
    return;
  }

  if( isnull( port ) && ! nofork && ! skip_port )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_app_location" );

  return get_app_details( cpe:cpe, type:"location", port:port, nofork:nofork, default:default );
}

# @brief Returns all ports (in the form of an array) of an app from a list of passed CPEs.
#
# @note This function will fork on multiple found applications.
#
# @param cpe_list       A list of CPEs to evaluate.
# @param service        A service to limit the returned ports to, e.g. "www" or "mysql".
# @param default        The default port to return in the case "optimize_test" is set to "no" and no
#                       port was found for the given CPE.
# @param first_cpe_only If set to "TRUE" only the info from the first passed CPE will be returned.
#                       Note that the function is still forking on multiple found ports for the same
#                       CPE.
#
# @return An array containing the port and CPE matching one of the specified CPEs, NULL in the case no CPE was
#         passed or no matching info was found. The array indices are the following:
#
#         ret_array["port"] = the found port
#         ret_array["cpe"]  = the CPE assigned to this specific port
#
function get_app_port_from_list( cpe_list, service, default, first_cpe_only ) {

  local_var cpe_list, service, default, first_cpe_only;
  local_var oid, cpe_count, _cpe, base_cpe, _ports, _port, services, _service, infos, _infos, ret_arr;

  oid = get_script_oid();

  if( ! cpe_list ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#cpe_list#-#get_app_port_from_list" );
    return;
  }

  if( typeof( cpe_list ) != "array" ) {
    set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#get_app_port_from_list: No list passed to cpe_list parameter" );
    return;
  }

  cpe_count = 0;

  foreach _cpe( cpe_list ) {

    if( ! base_cpe = get_base_cpe( cpe:_cpe ) ) {
      set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#get_app_port_from_list()#-#" + _cpe + "#-#cpe_list" );
      continue;
    }

    if( isnull( _ports = get_kb_list( "get_app/ports/" + base_cpe ) ) )
      continue;

    cpe_count++;

    foreach _port( _ports ) {

      if( _port == "local" )
        _port = 0; # nb: See function register_product

      if( service ) {
        services = get_kb_list( "get_app/services/" + _port + "/" + base_cpe );
        foreach _service( services ) {
          if( _port =~ "^[0-9]{1,5}$" && _service >< service )
            set_kb_item( name:"get_app/" + oid + "/port_cpe", value:_cpe + "#-#" + _port );
        }
      } else {
        if( _port =~ "^[0-9]{1,5}$" )
          set_kb_item( name:"get_app/" + oid + "/port_cpe", value:_cpe + "#-#" + _port );
      }
    }

    if( first_cpe_only && cpe_count > 0 )
      break;
  }

  infos = get_kb_item( "get_app/" + oid + "/port_cpe" );
  if( ! infos && default && optimize_test_enabled && "no" >< optimize_test_enabled ) {
    foreach _cpe( cpe_list )
      set_kb_item( name:"get_app/" + oid + "/port_cpe", value:_cpe + "#-#" + default );

    infos = get_kb_item( "get_app/" + oid + "/port_cpe" );
  }

  if( infos ) {
    _infos = split( infos, sep:"#-#", keep:FALSE );
    ret_arr["cpe"]  = _infos[0];
    ret_arr["port"] = _infos[1];
    return ret_arr;
  } else {
    return;
  }
}

# @brief Returns all versions (in the form of an array) of an app from a list of passed CPEs.
#
# @note This function will fork on multiple found applications.
#
# @param cpe_list      A list of CPEs to evaluate.
# @param port          The (optional) port of the application to get the version for, e.g. "80".
# @param nofork        If the function shouldn't fork and only return the first registered version (and not all available) of a
#                      specific CPE. Note that the function is still forking on multiple found applications with different CPEs.
# @param version_regex A regex to restrict the returned version to. E.g. if a version "1.2" was registered but a
#                      regex like "^[0-9]+\.[0-9]+\.[0-9]+" is specified the function won't return the version.
#
# @return An array containing the version and CPE matching one of the specified CPEs, NULL in the case no CPE list was
#         passed or no matching info was found. The array indices are the following:
#
#         ret_array["version"] = the found version
#         ret_array["cpe"]     = the CPE of the application for this specific version
#
function get_app_version_from_list( cpe_list, port, nofork, version_regex ) {

  local_var cpe_list, port, nofork, version_regex;
  local_var oid, _cpe, base_cpe, ap, ret_arr;

  oid = get_script_oid();

  if( ! cpe_list ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#cpe_list#-#get_app_version_from_list" );
    return;
  }

  if( typeof( cpe_list ) != "array" ) {
    set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#get_app_version_from_list: No list passed to cpe_list parameter" );
    return;
  }

  foreach _cpe( cpe_list ) {

    if( ! base_cpe = get_base_cpe( cpe:_cpe ) ) {
      set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version_from_list()#-#" + _cpe + "#-#cpe_list" );
      continue;
    }

    # Don't add the CPE to the list to evaluate below if the product wasn't detected
    if( isnull( get_kb_list( "get_app/ports/" + base_cpe ) ) )
      continue;

    set_kb_item( name:"get_app/" + oid + "/version_from_list", value:_cpe );
  }

  _cpe = get_kb_item( "get_app/" + oid + "/version_from_list" ); # nb: this could fork
  if( _cpe ) {
    ap = get_app_details( cpe:_cpe, type:"version", port:port, nofork:nofork, version_regex:version_regex );
    if( ap ) {
      ret_arr["cpe"]     = _cpe;
      ret_arr["version"] = ap;
      return ret_arr;
    }
  }
  return;
}

# @brief Returns all locations (in the form of an array) of an app from a list of passed CPEs.
#
# @note This function will fork on multiple found applications.
#
# @param cpe_list A list of CPEs to evaluate.
# @param port     The (optional) port of the application to get the location for, e.g. "80".
# @param nofork   If the function shouldn't fork and only return the first registered location (and not all available) of a
#                 specific CPE. Note that the function is still forking on multiple found applications with different CPEs.
#
# @return An array containing the location and CPE matching one of the specified CPEs, NULL in the case no CPE list was
#         passed or no matching info was found. The array indices are the following:
#
#         ret_array["location"] = the found location
#         ret_array["cpe"]      = the CPE of the application for this specific location
#
function get_app_location_from_list( cpe_list, port, nofork ) {

  local_var cpe_list, port, nofork;
  local_var oid, _cpe, base_cpe, ap, ret_arr;

  oid = get_script_oid();

  if( ! cpe_list ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#cpe_list#-#get_app_location_from_list" );
    return;
  }

  if( typeof( cpe_list ) != "array" ) {
    set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#get_app_location_from_list: No list passed to cpe_list parameter" );
    return;
  }

  foreach _cpe( cpe_list ) {

    if( ! base_cpe = get_base_cpe( cpe:_cpe ) ) {
      set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#get_app_location_from_list()#-#" + _cpe + "#-#cpe_list" );
      continue;
    }

    # Don't add the CPE to the list to evaluate below if the product wasn't detected
    if( isnull( get_kb_list( "get_app/ports/" + base_cpe ) ) )
      continue;

    set_kb_item( name:"get_app/" + oid + "/location_from_list", value:_cpe );
  }

  _cpe = get_kb_item( "get_app/" + oid + "/location_from_list" ); # nb: this could fork
  if( _cpe ) {
    ap = get_app_details( cpe:_cpe, type:"location", port:port, nofork:nofork );
    if( ap ) {
      ret_arr["cpe"]      = _cpe;
      ret_arr["location"] = ap;
      return ret_arr;
    }
  }
  return;
}

# @brief Returns all versions (in the form of an array) and their location of an app from a list of passed CPEs.
#
# @note This function will fork on multiple found applications.
#
# @param cpe_list         A list of CPEs to evaluate.
# @param port             The (optional) port of the application to get the version and location for, e.g. "80".
# @param exit_no_version  If the function should exit if no version was found. Note: The function
#                         still returns data (means it doesn't exit) if a version but no location
#                         was found.
# @param version_regex    A regex to restrict the returned version to. E.g. if a version "1.2" was registered but a
#                         regex like "^[0-9]+\.[0-9]+\.[0-9]+" is specified the function won't return the version.
# @param default_location The default location to return in the case "optimize_test" is set to "no" and no location was found for the given CPE.
#
# @return An array containing the version, CPE and location matching one of the specified CPEs, NULL in the case no CPE list was
#         passed or no matching info was found. The array indices are the following:
#
#         ret_array["version"]  = the found version
#         ret_array["location"] = the found location
#         ret_array["cpe"]      = the CPE of the application for this specific version and location
#
function get_app_version_and_location_from_list( cpe_list, port, exit_no_version, version_regex, default_location ) {

  local_var cpe_list, port, exit_no_version, version_regex, default_location;
  local_var oid, _cpe, base_cpe, ap, ret_arr;

  oid = get_script_oid();

  if( ! cpe_list ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#cpe_list#-#get_app_version_from_list" );
    return;
  }

  if( typeof( cpe_list ) != "array" ) {
    set_kb_item( name:"vt_debug_misc/" + oid, value:oid + "#-#get_app_version_from_list: No list passed to cpe_list parameter" );
    return;
  }

  foreach _cpe( cpe_list ) {

    if( ! base_cpe = get_base_cpe( cpe:_cpe ) ) {
      set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version_and_location_from_list()#-#" + _cpe + "#-#cpe_list" );
      continue;
    }

    # Don't add the CPE to the list to evaluate below if the product wasn't detected
    if( isnull( get_kb_list( "get_app/ports/" + base_cpe ) ) )
      continue;

    set_kb_item( name:"get_app/" + oid + "/version_and_location_from_list", value:_cpe );
  }

  _cpe = get_kb_item( "get_app/" + oid + "/version_and_location_from_list" ); # nb: this could fork
  if( _cpe ) {

    ap = get_app_details( cpe:_cpe, type:"version_location", port:port, exit_no_version:exit_no_version, version_regex:version_regex, default_location:default_location );
    # nb: This is used here as get_app_details() might return earlier with NULL without even
    # reaching the exit_no_version check in the "version_location" part.
    if( isnull( ap ) && exit_no_version )
      exit( 0 );

    # nb: This is for the "optimize_test" = "no" case where app_details above might contain an empty version index
    if( ap && ! ap["version"] && exit_no_version )
      exit( 0 );

    ret_arr        = ap;
    ret_arr["cpe"] = _cpe;
    return ret_arr;
  }
  return;
}

# @brief Returns one or more ports of an app / product matching the specified CPE and data.
#
# @param cpe     A single CPE (as a string) to evaluate.
# @param service A service to limit the returned ports to, e.g. "www" or "mysql".
# @param default The default port to return in the case "optimize_test" is set to "no" and no port was found
#                for the given CPE.
#
# @note This function will fork on multiple open / found ports for the same CPE.
#
# @return A port matching the specified CPE and data, NULL in the case no CPE was passed or no matching info was found.
#
function get_app_port( cpe, service, default ) {

  local_var cpe, service, default;
  local_var base_cpe, port, services;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_port" );
    return;
  }

  # nb: Older variants of this function allowed to pass a string or a list of CPEs via the "cpe" parameter. This was
  # unexpected / broken by design and removed later (also from all known VTs doing this) but we still want to do some
  # additional logging in case one got missed or there are private VTs out there doing the same.
  if( typeof( cpe ) == "array" ) {
    if( ! cpe[0] ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_port: List with an empty element passed to the 'cpe' parameter. Please only pass a single CPE in form of a string to this function." );
      return;
    } else {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_port: Passing a list of CPEs to the 'cpe' parameter is deprecated / unsupported. Only using the first CPE from this list." );
      cpe = cpe[0];
    }
  }

  if( ! base_cpe = get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#get_app_port()#-#" + cpe + "#-#cpe" );
    return;
  }

  port = get_kb_item( "get_app/ports/" + base_cpe ); # this could fork
  if( port == "local" )
    port = 0; # nb: See function register_product

  if( service ) {
    services = get_kb_item( "get_app/services/" + port + "/" + base_cpe ); # nb: this could fork
    if( port =~ "^[0-9]{1,5}$" && services >< service )
      return port;
  } else {
    if( port =~ "^[0-9]{1,5}$" )
      return port;
  }

  if( default && optimize_test_enabled && "no" >< optimize_test_enabled )
    return default;
  else
    return;
}

# @brief Returns the version and location of an application registered for the remote host within the KB matching the specified data.
#
# @param cpe              The CPE to get the version and location for.
# @param port             The port of the application to get the version and location for, e.g. "80".
# @param exit_no_version  If the function should exit if no version was found. Note: The function
#                         still returns data (means it doesn't exit) if a version but no location
#                         was found.
# @param version_regex    A regex to restrict the returned version to. E.g. if a version "1.2" was registered but a
#                         regex like "^[0-9]+\.[0-9]+\.[0-9]+" is specified the function won't return the version.
# @param default_location The default location to return in the case "optimize_test" is set to "no" and no location was found for the given CPE.
#
# @return An array containing the info about the application matching the specified data in a form of the following array keys:
#
#         ["version"]
#         ["location"]
#
#         or NULL in the case no CPE was passed or no matching info was found.
#
# @note get_app_version_and_location() should be used instead of get_app_version() and get_app_location() together in a single VT if both information is required.
#
function get_app_version_and_location( cpe, port, exit_no_version, version_regex, default_location ) {

  local_var cpe, port, exit_no_version, version_regex, default_location;
  local_var app_details;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_version_and_location" );
    return;
  }

  app_details = get_app_details( cpe:cpe, type:"version_location", port:port, exit_no_version:exit_no_version, version_regex:version_regex, default_location:default_location );
  # nb: This is used here as get_app_details() might return earlier with NULL without even
  # reaching the exit_no_version check in the "version_location" part.
  if( isnull( app_details ) && exit_no_version )
    exit( 0 );

  # nb: This is for the "optimize_test" = "no" case where app_details above might contain an empty version index
  if( app_details && ! app_details["version"] && exit_no_version )
    exit( 0 );

  return app_details;
}

# @brief Returns the location and protocol of an application registered for the remote host within the KB matching the specified data.
#
# @param cpe              The CPE to get the location and protocol for.
# @param port             The port of the application to get the location and protocol for, e.g. "80".
# @param default_location The default location to return in the case "optimize_test" is set to "no" and no location was found for the given CPE.
# @param default_proto    The default protocol to return in the case "optimize_test" is set to "no" and no protocol was found for the given CPE.
#
# @return An array containing the info about the application matching the specified data in a form of the following array keys:
#
#         ["location"]
#         ["proto"]
#
#         or NULL in the case no CPE was passed or no matching info was found.
#
function get_app_location_and_proto( cpe, port, default_location, default_proto ) {

  local_var cpe, port, default_location, default_proto;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_location_and_proto" );
    return;
  }

  return get_app_details( cpe:cpe, type:"location_proto", port:port, default_location:default_location, default_proto:default_proto );
}

# @brief Returns the version and protocol of an application registered for the remote host within the KB matching the specified data.
#
# @param cpe             The CPE to get the version and protocol for.
# @param port            The port of the application to get the version and protocol for, e.g. "80".
# @param exit_no_version If the function should exit if no version was found. Note: The function
#                        still returns data (means it doesn't exit) if a version but no protocol was
#                        found.
# @param default_proto   The default protocol to return in the case "optimize_test" is set to "no" and no protocol was found for the given CPE.
#
# @return An array containing the info about the application matching the specified data in a form of the following array keys:
#
#         ["version"]
#         ["proto"]
#
#         or NULL in the case no CPE was passed or no matching info was found.
#
function get_app_version_and_proto( cpe, port, exit_no_version, default_proto ) {

  local_var cpe, port, exit_no_version, default_proto;
  local_var app_details;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_version_and_proto" );
    return;
  }

  app_details = get_app_details( cpe:cpe, type:"version_proto", port:port, exit_no_version:exit_no_version, default_proto:default_proto );
  # nb: This is used here as get_app_details() might return earlier with NULL without even
  # reaching the exit_no_version check in the "version_proto" part.
  if( isnull( app_details ) && exit_no_version )
    exit( 0 );

  # nb: This is for the "optimize_test" = "no" case where app_details above might contain an empty version index
  if( app_details && ! app_details["version"] && exit_no_version )
    exit( 0 );

  return app_details;
}

# @brief Returns all known information like location, port, version, protocol and service for the remote host within the KB matching the specified data.
#
# @param cpe             The CPE to get the information for.
# @param port            The port of the application to get the information for, e.g. "80".
# @param exit_no_version If the function should exit if no version was found. Note: The function
#                        still returns data (means it doesn't exit) if a version but e.g. no
#                        protocol or location was found.
#
# @return An array containing the info about the application matching the specified data in a form of the following array keys:
#
#         ["version"]
#         ["location"]
#         ["full_cpe"]
#         ["port"]
#         ["proto"]
#         ["service"]
#         ["detected_by"]
#         ["internal_version"]
#
#         or NULL in the case no CPE was passed or no matching info was found.
#
function get_app_full( cpe, port, exit_no_version ) {

  local_var cpe, port, exit_no_version;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_full" );
    return;
  }

  return get_app_details( cpe:cpe, type:"full", port:port, exit_no_version:exit_no_version );
}

# @brief Returns the port from a CPE prefix / vendor part. For example "cpe:/o:cisco:rv110w_firmware" is the
#   full CPE and the function is accepting e.g. "cpe:/o:cisco:rv" to get the port for all vendor devices.
#
# @note This function might fork on multiple found ports.
#
# @param cpe            The CPE prefix / vendor part (e.g. cpe:/h:qnap) to get the port for.
# @param default        The default port to return in the case "optimize_test" is set to "no" and no
#                       port was found for the given CPE prefix / vendor part.
# @param service        A service to limit the returned ports to, e.g. "www" or "mysql".
# @param first_cpe_only If set to "TRUE" only the info from the first passed CPE will be returned.
#                       Note that the function is still forking on multiple found ports for the same
#                       CPE.
#
# @return An array containing the port and CPE matching the specified CPE prefix / vendor part, NULL in the case
#         no CPE prefix / vendor part was passed or no matching info was found. The array indices are the following:
#
#         ret_array["port"] = the found port
#         ret_array["cpe"]  = the CPE assigned to this specific port
#
function get_app_port_from_cpe_prefix( cpe, default, service, first_cpe_only ) {

  local_var cpe, default, service, first_cpe_only;
  local_var data, _cpelist, _entry, parts, _cpe;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_port_from_cpe_prefix" );
    return;
  }

  data = get_kb_list( "get_app/ports/" + cpe + "*" );
  if( ! data )
    return;

  _cpelist = make_list();

  foreach _entry( keys( data ) ) {

    if( cpe >!< _entry )
      continue;

    parts = split( _entry, sep:"/", keep:FALSE );

    if( max_index( parts ) < 4 )
      continue;

    if( parts[2] != "cpe:" )
      continue;

    _cpe = parts[2] + "/" + parts[3];

    if( cpe >!< _cpe )
      continue;

    _cpelist = make_list( _cpelist, _cpe );
  }

  return get_app_port_from_list( cpe_list:_cpelist, service:service, default:default, first_cpe_only:first_cpe_only );
}

# @brief Internal function not to be used directly, please use the other wrappers
#        within this include calling this function.
#
function get_app_details( cpe, type, port, exit_no_version, service, nofork, version_regex, default, default_location, default_proto ) {

  local_var cpe, type, port, exit_no_version, service, nofork, version_regex, default, default_location, default_proto;
  local_var base_cpe, version_list, ap, _dt, t, t_cpe, t_port, app_versions, app_locations;
  local_var t_oid, t_loc, app_details, ret_arr, x, x_oid, x_cpe, x_loc, x_port, x_proto, x_service, x_internal_version;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_details" );
    return;
  }

  if( ! base_cpe = get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#get_app_details()#-#" + cpe + "#-#cpe" );
    return;
  }

  # "1.3.6.1.4.1.25623.1.0.xxxxx#-#cpe:/a:foo:bar:1.1.0#-#/foo#-#80" or
  # "1.3.6.1.4.1.25623.1.0.xxxxx#-#cpe:/a:foo:bar:1.1.0#-#/foo#-#80#-#www"
  if( type == "all_versions" ) {

    version_list = make_list();

    ap = get_kb_list( "get_app/" + base_cpe );
    if( ! ap )
      return;

    foreach _dt( ap ) {

      t = split( _dt, sep:"#-#", keep:FALSE );
      t_cpe = t[1];
      if( ! t_cpe )
        continue;

      t_port = t[3];
      if( ! isnull( port ) && int( t_port ) != int( port ) )
        continue;

      if( ! app_versions = get_version_from_cpe( cpe:t_cpe ) )
        continue;

      version_list = make_list( version_list, app_versions );
    }

    register_host_detail( name:"detected_by", value:t[0] );
    if( ! isnull( t[2] ) )
      register_host_detail( name:"detected_at", value:t[2] );

    return version_list;

  } else if( nofork && type == "version" ) { # nofork is currently only valid for get_app_version() and get_app_location()

    ap = get_kb_list( "get_app/" + base_cpe );
    if( ! ap )
      return;

    foreach _dt( ap ) {

      t = split( _dt, sep:"#-#", keep:FALSE );
      t_cpe = t[1];
      if( ! t_cpe )
        continue;

      t_port = t[3];
      if( ! isnull( port ) && int( t_port ) != int( port ) )
        continue;

      if( ! app_versions = get_version_from_cpe( cpe:t_cpe ) )
        continue;

      if( version_regex && ! ereg( pattern:version_regex, string:app_versions ) )
        continue;

      register_host_detail( name:"detected_by", value:t[0] );
      if( ! isnull( t[2] ) )
        register_host_detail( name:"detected_at", value:t[2] );

      return app_versions;
    }
    return; # no version...
  } else if( nofork && type == "location" ) { # nofork is currently only valid for get_app_version() and get_app_location

    ap = get_kb_list( "get_app/" + base_cpe );
    if( ! ap && default && optimize_test_enabled && "no" >< optimize_test_enabled )
      return make_list( default );
    else if( ! ap )
      return;

    app_locations = make_list();

    foreach _dt( ap ) {

      t = split( _dt, sep:"#-#", keep:FALSE );
      t_oid = t[0];
      t_loc = t[2];
      if( isnull( t_oid ) && isnull( t_loc ) )
        continue;

      t_port = t[3];
      if( ! isnull( port ) && int( t_port ) != int( port ) )
        continue;

      register_host_detail( name:"detected_by", value:t_oid );
      if( ! isnull( t[2] ) )
        register_host_detail( name:"detected_at", value:t_loc );

      app_locations = make_list( app_locations, t_loc );
    }
    return app_locations;
  } else {
    app_details = get_kb_item( "get_app/" + base_cpe ); # this could fork
  }

  # nb: This is kept here as we don't get any "app_details" from above if
  # no app was detected previously and the "default" is used.
  if( ! app_details && optimize_test_enabled && "no" >< optimize_test_enabled ) {

    if( type == "location" && default ) {
      return default;
    } else if( type == "version_location" && default_location ) {
      ret_arr["version"]  = "";
      ret_arr["location"] = default_location;
      return ret_arr;
    } else if( type == "version_proto" && default_proto ) {
      ret_arr["version"] = "";
      ret_arr["proto"]   = default_proto;
      return ret_arr;
    } else if( type == "location_proto" && ( default_proto || default_location ) ) {
      if( default_proto )
        ret_arr["proto"] = default_proto;
      else
        ret_arr["proto"] = "tcp";

      if( default_location )
        ret_arr["location"] = default_location;
      else
        ret_arr["location"] = "";

      return ret_arr;
    } else {
      return;
    }
  } else if( ! app_details ) {
    return;
  }

  x = split( app_details, sep:"#-#", keep:FALSE );

  x_oid       = x[0];
  x_cpe       = x[1];
  x_loc       = x[2];
  x_port      = x[3];
  x_proto     = x[4];
  if( x[5] )
    x_service = x[5];
  if( x[6] )
    x_internal_version = x[6];

  if( service && x_service != service )
    return;

  if( ! isnull( port ) && int( x_port ) != int( port ) )
    return;

  if( type == "version" ) {

    if( ! app_versions = get_version_from_cpe( cpe:x_cpe ) )
      return;

    if( version_regex && ! ereg( pattern:version_regex, string:app_versions ) )
      return;

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc )
      register_host_detail( name:"detected_at", value:x_loc );

    return app_versions;
  }

  if( type == "location" ) {

    if( x_loc ) {
      register_host_detail( name:"detected_by", value:x_oid );
      if( x_loc )
        register_host_detail( name:"detected_at", value:x_loc );

      return x_loc;
    }
    return;
  }

  if( type == "version_location" ) {

    app_versions = get_version_from_cpe( cpe:x_cpe );

    if( ! app_versions && exit_no_version == TRUE )
      exit( 0 );

    if( ! app_versions && ! x_loc )
      return;

    if( app_versions ) {

      if( version_regex && ! ereg( pattern:version_regex, string:app_versions ) )
        return;

      ret_arr["version"] = app_versions;
    } else {
      ret_arr["version"] = "";
    }

    if( x_loc )
      ret_arr["location"] = x_loc;
    else
      ret_arr["location"] = "";

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc )
      register_host_detail( name:"detected_at", value:x_loc );

    return ret_arr;
  }

  if( type == "version_proto" ) {

    app_versions = get_version_from_cpe( cpe:x_cpe );

    if( ! app_versions && exit_no_version == TRUE )
      exit( 0 );

    if( ! app_versions && ! x_proto )
      return;

    if( app_versions )
      ret_arr["version"] = app_versions;
    else
      ret_arr["version"] = "";

    if( x_proto )
      ret_arr["proto"] = x_proto;
    else
      ret_arr["proto"] = "tcp";

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_proto && x_port )
      register_host_detail( name:"detected_at", value:x_port + "/" + x_proto );

    return ret_arr;
  }

  if( type == "location_proto" ) {

    if( x_proto )
      ret_arr["proto"] = x_proto;
    else
      ret_arr["proto"] = "tcp";

    if( x_loc )
      ret_arr["location"] = x_loc;
    else
      ret_arr["location"] = "";

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc )
      register_host_detail( name:"detected_at", value:x_loc );

    return ret_arr;
  }

  if( type == "full" ) {

    app_versions = get_version_from_cpe( cpe:x_cpe );
    if( ! app_versions && exit_no_version == TRUE )
      exit( 0 );

    ret_arr["version"]     = app_versions;
    ret_arr["location"]    = x_loc;
    ret_arr["full_cpe"]    = x_cpe;
    ret_arr["port"]        = x_port;
    ret_arr["proto"]       = x_proto;
    if( x_service )
      ret_arr["service"]   = x_service;
    ret_arr["detected_by"] = x_oid;
    if( x_internal_version )
      ret_arr["internal_version"] = x_internal_version;

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc )
      register_host_detail( name:"detected_at", value:x_loc );

    return ret_arr;
  }
  return;
}

# @brief Returns the version from a specific CPE.
#
# @param cpe The CPE to get the version from, e.g.:
#
#            cpe:/a:vendor:product:1.2.3 -> 1.2.3 returned
#            cpe:/a:vendor:product:1.2.3:p1 -> 1.2.3p1 returned
#
# @return A string containing a version of the specific CPE, or NULL in the case no CPE was passed or no matching info was found.
#
# @note The function currently supports an (unfortunately wrong) used CPE syntax like cpe:/a:vendor:product:x64:1.2.3
#       and is returning the version from it as well.
#
function get_version_from_cpe( cpe ) {

  local_var cpe;
  local_var tokens, token_val, app_versions;

  if( isnull( cpe ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_version_from_cpe" );
    return;
  }

  tokens = split( cpe, sep:":", keep:FALSE );

  # Possible CPEs are e.g.
  # cpe:/a:extplorer:extplorer:2.1.0:RC5
  # cpe:/o:canonical:ubuntu_linux:12.04:-:lts
  # cpe:/o:microsoft:windows_7:-:-:x64
  # nb: Some are also setting a CPE with a wrong syntax like cpe:/a:vendor:product:x64:1.1
  # which should be cpe:/a:vendor:product:1.1:-:x64

  # Test-cases:
  # CPE: cpe:/a:foo0:bar0:x64:1.2.3 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo1:bar1:x64:1.2.3:RC1 , expected version: 1.2.3RC1 , returned version: 1.2.3RC1
  # CPE: cpe:/a:foo2:bar2:1.2.3 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo3:bar3:1.2.3:RC2 , expected version: 1.2.3RC2, returned version: 1.2.3RC2
  # CPE: cpe:/a:foo4:bar4:1.2.3:RC3:x64 , expected version: 1.2.3RC3, returned version: 1.2.3RC3
  # CPE: cpe:/a:foo5:bar5:1.2.3:RC4:x32 , expected version: 1.2.3RC4, returned version: 1.2.3RC4
  # CPE: cpe:/a:foo6:bar6:1.2.3:-:x64 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo7:bar7:1.2.3:-:x32 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo8:bar8:1.2.3::x64 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo9:bar9:1.2.3::x32 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo10:bar10:-:-:x64 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo11:bar11:-:-:x32 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo12:bar12:::x64 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo13:bar13:::x32 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo14:bar14::sp2:x64 , expected version: sp2, returned version: sp2
  # CPE: cpe:/a:foo15:bar15::sp2:x32 , expected version: sp2, returned version: sp2
  # CPE: cpe:/a:foo16:bar16:-:sp2:x64 , expected version: sp2, returned version: sp2
  # CPE: cpe:/a:foo17:bar17:-:sp2:x32 , expected version: sp2, returned version: sp2

  if( ! isnull( tokens[4] ) ) {

    # catch the wrong CPE syntax cpe:/a:foo0:bar0:x64:1.2.3 described above
    if( tokens[4] == "x64" )
      token_val = 1;
    else
      token_val = 0;

    # handle cpe:/a:foo3:bar3:1.2.3:RC2
    if( ! isnull( tokens[5 + token_val] ) && tokens[5 + token_val] != "-" && tokens[5 + token_val] != "" ) {

      if( tokens[4 + token_val] != "-" && tokens[4 + token_val] != "" )
        app_versions = tokens[4 + token_val] + "" + tokens[5 + token_val]; # handle cpe:/a:foo3:bar3:1.2.3:RC2
      else
        app_versions = tokens[5 + token_val]; # handle cpe:/a:foo10:bar10:-:sp2

    } else {
      # handle cpe:/a:foo2:bar2:1.2.3
      if( tokens[4 + token_val] != "-" && tokens[4 + token_val] != "" )
        app_versions = tokens[4 + token_val];
    }
  }

  if( ! app_versions )
    return;
  else
    return app_versions;
}

# @brief Returns the "base" CPE of a passed CPE without any version and similar, e.g.
#
#        cpe:/a:vendor:product:1.2.3 -> cpe:/a:vendor:product returned
#        cpe:/a:vendor:product:1.2.3:p1 -> cpe:/a:vendor:product returned
#
# @return A string containing a base of a specific CPE, or NULL in the case no CPE was passed or the CPE has a wrong syntax.
#
function get_base_cpe( cpe ) {

  local_var cpe;
  local_var bc, base_cpe;

  if( ! cpe )
    return;

  bc = split( cpe, sep:":", keep:FALSE );
  if( ! bc || max_index( bc ) < 4 )
    return;

  if( bc[0] != "cpe" || bc[1] !~ "/(a|o|h)$" )
    return;

  base_cpe = bc[0] + ":" + bc[1] + ":" + bc[2] + ":" + bc[3];

  return base_cpe;
}

# @brief Builds a detection report for an application with the passed data to be used by VTs in e.g. a log_message().
#
# @param app          The name of the application, e.g. "Vendor Productname".
# @param version      The version of the application.
# @param patch        The update- / patch-level of the application.
# @param build        The Build of the application.
# @param install      The install location of the application, e.g. 80/tcp or /path/to/folder.
# @param regpath      The path to a windows registry entry of the application.
# @param cpe          The CPE of the application
# @param concluded    The info including where the version was detected from.
# @param concludedUrl The URL where the version was detected from.
# @param extra        Any additional information which should be appended to the report.
# @param skip_version If no version was passed to the "version" parameter an "unknown" version is assumed.
#                     Setting this parameter to "TRUE" won't add any version information at all.
#
# @return A string containing a detection report for the passed data.

function build_detection_report( app, version, patch, build, install, regpath, cpe, concluded, concludedUrl, extra, skip_version ) {

  local_var app, version, patch, build, install, regpath, cpe, concluded, concludedUrl, extra, skip_version;
  local_var report;

  if( isnull( app ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#app#-#build_detection_report" );

  report = "Detected " + app + '\n';

  if( ! skip_version ) {
    if( ! version )
      version = "unknown";
    report += '\nVersion:       ' + version;
  }

  if( patch && patch != "unknown" )
    report += '\nPatch/Update:  ' + patch;

  if( build && build != "unknown" )
    report += '\nBuild:         ' + build;

  report += '\nLocation:      ' + install;

  if( strlen( cpe ) > 0 )
    report += '\nCPE:           '+ cpe;

  if( strlen( regpath ) > 0 )
    report += '\nRegistry path: '+ regpath;

  if( strlen( concluded ) > 0 && tolower( concluded ) != "unknown" )
    report += '\n\nConcluded from version/product identification result:\n' + concluded;

  if( strlen( concludedUrl ) > 0 )
    report += '\n\nConcluded from version/product identification location:\n' + concludedUrl;

  if( strlen( extra ) > 0 )
    report += '\n\nExtra information:\n' + extra;

  return report;
}
