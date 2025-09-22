# SPDX-License-Identifier: GPL-2.0-only
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-FileCopyrightText: 2025 Greenbone AG

# @brief Checks if the given date has been already reached.
#
# @param eol_date The date to check.
#
# @note If "unknown" is passed to the eol_date parameter TRUE is returned as well.
#
# @return TRUE if the given date has been already reached or NULL if not or not all mandatory
#         parameters have been given.
#
function eol_date_reached( eol_date ) {

  local_var eol_date;
  local_var local_time;

  if( ! eol_date ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_date#-#eol_date_reached" );
    return;
  }

  # Special case to mark an OS/Product as EOL if the date is unknown.
  # This avoids that we need to guess a date for e.g. older products.
  if( eol_date == "unknown" ) return TRUE;

  eol_date = str_replace( string:eol_date, find:"-", keep:FALSE );
  local_time = make_date_str( date:localtime( unixtime() ) );

  if( int( local_time ) >= int( eol_date ) )
    return TRUE;

  return;
}

# @brief Returns a string including a formatted report to include EOL info about either a product or
#        an OS.
#
# @param eol_type The mandatory type of the report, valid values are: prod, os
#
# @param name The name of the product / OS.
#
# @param cpe The CPE of the product / OS.
#
# @param version The version of the product / OS.
#
# @param location The location of the product / OS.
#
# @param skip_version If set to TRUE the version is not included in the report.
#
# @param eol_version The EOL version of the product / OS.
#
# @param eol_date The EOL date of the product / OS.
#
# @param eol_url The URL to additional resources to reach about the EOL of the product / OS.
#
# @return A string formatted like described or an empty string if no supported report "type" was given.
#
function eol_build_message( eol_type, name, cpe, version, location, skip_version, eol_version, eol_date, eol_url ) {

  local_var eol_type, name, cpe, version, location, skip_version, eol_version, eol_date, eol_url;
  local_var report;

  if( eol_type != "prod" && eol_type != "os" ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_build_message: Wrong value passed to eol_type. Valid values are: prod, os" );
    return "";
  }

  if( eol_type == "prod" ) {

    if( ! name )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#eol_build_message" );

    if( ! cpe )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#eol_build_message" );

    if( ! version && ! skip_version )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#eol_build_message" );

    if( ! eol_version && ! skip_version )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_version#-#eol_build_message" );

    if( ! eol_date )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_date#-#eol_build_message" );

    if( ! skip_version ) {
      report = 'The "' + name + '" version on the remote host has reached the end of life.\n\n' +
               "CPE:               " + cpe;
      if( tolower( version ) != "unknown" )
        report += ":" + version;
      report += '\nInstalled version: ' + version;
    } else {
      report = 'The "' + name + '" product on the remote host has reached the end of life.\n\n' +
               'CPE:               ' + cpe;
    }

    if( location )
      report += '\nLocation/URL:      ' + location;

    if( eol_version )
      report += '\nEOL version:       ' + eol_version;

    if( eol_date )
      report += '\nEOL date:          ' + eol_date;

    if( eol_url )
      report += '\nEOL info:          ' + eol_url;

  } else if( eol_type == "os" ) {

    if( ! name )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#eol_build_message" );

    if( ! cpe )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#eol_build_message" );

    if( ! eol_date )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_date#-#eol_build_message" );

    if( ! eol_url )
      set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#eol_url#-#eol_build_message" );

    report = 'The "' + name + '" Operating System on the remote host has reached the end of life.\n\n' +
             'CPE:               ' + cpe;

    if( version && version != "unknown" ) {
      report += '\nInstalled version,\n';
      report += 'build or SP:       ' + version;
    }

    if( eol_version )
      report += '\nEOL version:       ' + eol_version;

    if( eol_date )
      report += '\nEOL date:          ' + eol_date;

    if( eol_url )
      report += '\nEOL info:          ' + eol_url;
  }
  return report;
}
