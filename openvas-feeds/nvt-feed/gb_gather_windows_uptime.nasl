# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96175");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2016-01-26 09:31:15 +0100 (Tue, 26 Jan 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Windows uptime");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_login.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_mandatory_keys("login/SMB/success");

  script_tag(name:"summary", value:"Gather the 'uptime' from a Windows host and stores the results
  in the KB.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if( is_win_cmd_exec_disabled() )
  exit( 0 );

# nb: This command outputs the date in the same format as it was before, when using WMI query
query = "[System.Management.ManagementDateTimeConverter]::ToDmtfDateTime((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)";
uptime = powershell_cmd( cmd:query );

if( uptime ) {
  uptime_match = eregmatch( pattern:'^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})', string: uptime );
  if( isnull( uptime_match[0] ) )
    exit( 0 );

  uptime = mktime( sec:uptime_match[6], min:uptime_match[5], hour:uptime_match[4], mday:uptime_match[3], mon:uptime_match[2], year:uptime_match[1] );
  register_host_detail( name:"uptime", value:uptime );
  set_kb_item( name:"Host/uptime", value:uptime );
}

exit( 0 );
