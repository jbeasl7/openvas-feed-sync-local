# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Saves the given package list string into the KB for LSC via notus.
#
# @param os_release The OS release
# @param pkg_list   The package list
# @param rpms       If the packages list is RPM
#
# @return TRUE if the OS release string and package were registered, FALSE otherwise and NULL
#         if the "os_release" or "pkg_list" string was empty / wasn't passed.
#

include("pkg-lib-rpm.inc");

function register_notus( os_release, pkg_list, rpms ) {

  local_var os_release, pkg_list, rpms, results, result, pkg_key_name;

  if( ! os_release ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#register_notus#-#os_release" );
    return NULL;
  }

  if( ! pkg_list ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#register_notus#-#pkg_list" );
    return NULL;
  }

  if( rpms == TRUE && ! check_rpms( buf:pkg_list ) )
    return FALSE;

  if( defined_func( "notus" ) && defined_func( "security_notus" ) && defined_func( "notus_error" ) ) {
    set_kb_item( name:"vt_debug_notus/" + get_script_oid(), value:get_script_oid() + "#-#register_notus#-#os_release: '" + os_release + "'");
    set_kb_item( name:"vt_debug_notus/" + get_script_oid(), value:get_script_oid() + "#-#register_notus#-#pkg_list: '" + pkg_list + "'");

    results = notus( pkg_list: pkg_list, product: os_release );
    if ( ! results ) {
      log_message( data:"There was an error while executing a Notus scan: '" + notus_error() + "'" );
      return FALSE;
    }

    foreach result ( results ) {
      security_notus(result: result);
    }

    return TRUE;
  }

  if( defined_func( "update_table_driven_lsc_data" ) ) {
    update_table_driven_lsc_data( pkg_list:pkg_list, os_release:os_release );
    return TRUE;
  }

  # Store OS release
  set_kb_item( name:"ssh/login/release_notus", value:os_release );

  # Store package list for RPM
  pkg_key_name = "ssh/login/package_list_notus";
  if( rpms == TRUE ) {
    if( ! register_rpms( buf:pkg_list, custom_key_name:pkg_key_name, skip_check:TRUE ) )
      return FALSE;

    return TRUE;
  }

  # Store package list for non-RPM
  set_kb_item( name:pkg_key_name, value:pkg_list );
}