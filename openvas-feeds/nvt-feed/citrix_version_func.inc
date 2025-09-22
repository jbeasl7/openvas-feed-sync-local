# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

function citrix_xenserver_check_report_is_vulnerable( version, hotfixes, patches ) {

  local_var version, hotfixes, patches;
  local_var a, av, fixes, _patch;

  if( ! version || ! patches || ! hotfixes ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version_patches_hotfixes#-#citrix_xenserver_check_report_is_vulnerable" );
    return;
  }

  if( ! is_array( patches ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#patches_no_array#-#citrix_xenserver_check_report_is_vulnerable" );
    return;
  }

  a = eregmatch( pattern:"^([0-9]\.[0-9]\.[0-9])", string:version );
  if( isnull( a[1] ) )
    return;

  av = a[1];

  if( ! is_array( patches[ av ] ) )
    return;

  if( "No hotfixes installed" >< hotfixes )
    citrix_xenserver_report_missing_patch( version:version, fix:patches[av] );

  fixes = make_list();

  foreach _patch( patches[ av ] ) {
    if( ( "ECC" >< hotfixes && "ECC" >!< _patch ) || ( "ECC" >< _patch && "ECC" >!< hotfixes ) )
      continue;

    if( _patch >!< hotfixes )
      fixes = make_list( fixes, _patch );
  }

  if( is_array( fixes ) )
    citrix_xenserver_report_missing_patch( version:version, fix:fixes );

  return;
}

function citrix_xenserver_report_missing_patch( version, fix ) {

  local_var version, fix;
  local_var report;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version_#-#citrix_xenserver_report_missing_patch" );

  if( ! fix )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fix#-#citrix_xenserver_report_missing_patch" );

  report  = 'Installed version: ' + version + '\n';
  report += 'Missing hotfix:    ' + join( list:fix, sep:" / " );
  security_message( port:0, data:report );
  exit( 0 );
}
