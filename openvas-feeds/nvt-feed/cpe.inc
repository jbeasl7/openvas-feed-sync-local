# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Extends a given CPE base (like e.g. cpe:/a:vendor:product:) with
#        a given value if the passed expression in the exp is matching this value.
#
# @param value The value to append to the given CPE base.
# @param exp   The regex expression where the given value needs to be match against.
# @param base  The CPE base in the form of cpe:/a:vendor:product:
#
# @return A string containing the CPE base with the appended value (if the expression has matched),
#         NULL otherwise.
#
function build_cpe( value, exp, base ) {

  local_var value, exp, base;
  local_var res, last;

  if( ! value ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#value#-#build_cpe" );
    return NULL;
  }

  if( ! exp ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#exp#-#build_cpe" );
    return NULL;
  }

  if( ! base ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#base#-#build_cpe" );
    return NULL;
  }

  if( ! get_base_cpe( cpe:base ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#build_cpe()#-#" + base + "#-#base" );
    return NULL;
  }

  if( value == "unknown" || value == "Unknown" || strlen( value ) < 1 )
    return NULL;

  res = eregmatch( string:value, pattern:exp, icase:TRUE );
  if( res[1] ) {
    last = strlen( base ) - 1;
    if( ":" >!< base[last] ) {
      return base;
    } else if( res[1] && res[2] ) {
      return string( base, res[1], ":", res[2] );
    } else if( res[1] ) {
      return string( base, res[1] );
    }
  }
  return NULL;
}

# @brief Registers a given product CPE with the given info in the knowledge base.
#        Additionally it will build a report message about this detection and sends it via a
#        log_message() to the manager.
#
# @param app        The Name of the App which should be registered, this is included in the report message.
# @param ver        The Version of the App which should be registered.
# @param concluded  The text string where the product detection was concluded from.
# @param cpename    A full CPE string in the form of e.g. cpe:/a:vendor:product or cpe:/a:vendor:product:1.2.3 which should be registered.
# @param base       A base CPE string in the form of e.g. cpe:/a:vendor:product: which is used to build a CPE with an appended version.
# @param expr       A regex expression which is used to match the ver parameter against and which is added to the base CPE if a match was found.
# @param insloc     The location/URL where the product was detected.
# @param regPort    The Port where the product was detected.
# @param regService The Service (e.g. www, ftp, snmp) where the product was detected.
# @param regProto   The network protocol (e.g. tcp, udp) where the product was detected.
# @param conclUrl   The URL/location where the product was detected from.
# @param extra      Any extra information which should be added to the report message.
# @param cpeLower   If the CPE should be made lowercase (Default: no)
#
# @return NULL
#
function register_and_report_cpe( app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra, cpeLower ) {

  local_var app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra, cpeLower;

  if( ! cpename && ! base && ! expr ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpename,base,expr#-#register_and_report_cpe" );
    return NULL;
  }

  if( ! cpename && ( base && ! expr ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#expr#-#register_and_report_cpe" );
    return NULL;
  }

  if( ! cpename && ( ! base && expr ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#base#-#register_and_report_cpe" );
    return NULL;
  }

  if( cpename && base )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#register_and_report_cpe(): cpename and base parameter given, please use only one!" );

  if( cpename && ! get_base_cpe( cpe:cpename ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#register_and_report_cpe()#-#" + cpename + "#-#cpename" );
    return NULL;
  }

  if( base && ! get_base_cpe( cpe:base ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#register_and_report_cpe()#-#" + base + "#-#base" );
    return NULL;
  }

  if( ! insloc )
    insloc = "unknown";

  if( ! concluded && ver )
    concluded = ver;

  if( ! ver || ver == "" || ver == "Unknown" )
    ver = "unknown";

  if( ! regProto )
    regProto = "tcp";

  # nb: make sure that we're at least registering a default port to 0 for local detections via e.g. SSH
  if( isnull( regPort ) )
    regPort = 0;

  if( ! cpename && base ) {
    cpename = build_cpe( value:ver, exp:expr, base:base );
    if( ! cpename || ver == "unknown" )
      cpename = ereg_replace( pattern:":$", string:base, replace:"" );

  }

  if( cpename ) {

    if( cpeLower )
      cpename = tolower( cpename );

    register_product( cpe:cpename, location:insloc, port:regPort, proto:regProto, service:regService );

    log_message( data:build_detection_report( app:app,
                                              version:ver,
                                              install:insloc,
                                              cpe:cpename,
                                              extra:extra,
                                              concluded:concluded,
                                              concludedUrl:conclUrl ),
                 port:regPort,
                 proto:regProto );
  }
  return NULL;
}
