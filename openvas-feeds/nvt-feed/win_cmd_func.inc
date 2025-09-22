# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Performs any arbitrary command against a Windows host
#
# @param cmd The command to run
#
# @return A string with the command result from the Windows host, NULL if no result was returned or
#         not all mandatory function parameters have been given
#
function win_run_cmd( cmd ) {
  local_var cmd;
  local_var infos, result;

  if( ! defined_func( "win_cmd_exec" ) )
    return;

  if( ! infos = kb_smb_wmi_connectinfo() )
    return;

  if( ! cmd ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#win_run_cmd" );
    return;
  }

  if( ! get_kb_item( "login/SMB/kerberos/success" ) ) {
    result = win_cmd_exec( cmd:cmd, password:infos["password"], username:infos["username_wincmd"] );
  } else {
    result = win_cmd_exec( cmd:cmd, password:infos["password"], username:infos["username_wincmd"],
                           realm:infos["domain"], kdc:infos["kdc"], host:infos["hostname"] );
  }

  if( ! result = chomp( result ) )
    return;

  # Get rid of wmiexec.py prefix and any trailing / leading whitespaces
  result = ereg_replace( string:result, pattern:"(Impacket .+ dialect used)", replace:"" );
  result = ereg_replace( string:chomp( result ), pattern:"^\s+", replace:"" );
  if( result )
    return( result );

  return;
}
