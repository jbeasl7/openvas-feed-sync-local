# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96198");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-09-08 13:13:18 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows File-Shares, shared for Everyone");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_ms_wmi_accessible_shares.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("login/SMB/success", "WMI/Accessible_Shares");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"Get Windows File-Shares, shared for Everyone.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("win_cmd_func.inc");
include("powershell_func.inc");

if( is_win_cmd_exec_disabled() )
  exit( 0 );

shares  = get_kb_item( "WMI/Accessible_Shares" );

cmd = "Get-WmiObject -Class Win32_SystemAccount | Where-Object { $_.SID -eq 'S-1-1-0' } |  ForEach-Object { $_.Name };";
se = powershell_cmd( cmd:cmd );

sl = split( shares, keep:FALSE );

# nb: Starting with 1 as sl[0] contains the header
for( a = 1; a < max_index( sl ); a++ ) {

  READ   = NULL;
  CHANGE = NULL;
  FULL   = NULL;
  RES    = NULL;

  s    = split( sl[a], sep:'|', keep:FALSE );
  fold = eregmatch( pattern:":", string:s[2] );
  desc = s[0];
  name = s[1];
  path = s[2];
  if( isnull( desc ) || desc == "" )
    desc = "None";

  if( fold ) {
    c   = "net share " + name;
    val = win_run_cmd( cmd:c );

    READ   = eregmatch( string:val, pattern:se + ", READ" );
    CHANGE = eregmatch( string:val, pattern:se + ", CHANGE" );
    FULL   = eregmatch( string:val, pattern:se + ", FULL" );

    if( READ[0] )   RES = name + "|" + path + "|" +  READ[0] + "|" + desc + '\n';
    if( CHANGE[0] ) RES = name + "|" + path + "|" +  CHANGE[0] + "|" + desc + '\n';
    if( FULL[0] )   RES = name + "|" + path + "|" +  FULL[0] + "|" + desc + '\n';

    result += RES;
  }
}

if( result ) {
  report  = "The following File-Shares are shared for Everyone (local name: '" + se + "'):" + '\n\n';
  report += 'Name|Path|Access|Description\n' + result;
  log_message( port:0, data:report );
}

exit( 0 );
