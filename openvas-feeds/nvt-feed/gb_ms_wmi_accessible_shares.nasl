# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96199");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-03-12 09:32:24 +0200 (Wed, 12 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows File-Shares over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_login.nasl", "lsc_options.nasl");
  script_mandatory_keys("login/SMB/success");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"Get Windows File-Shares over WMI.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if( is_win_cmd_exec_disabled() )
  exit( 0 );
# nb: 2015/gb_ms_wmi_everyone_file-shares.nasl relies on the
# three items returned here so update this as well if more
# objects are queried here.
sharelist = powershell_wmi_query( classname:"Win32_share", properties:"Description,Name,Path" );

if( sharelist ) {
  # nb: Added to keep the previous format / reporting
  sharelist = ereg_replace( string:sharelist, pattern:";", replace:"|" );
  set_kb_item( name:"WMI/Accessible_Shares", value:sharelist );
  report = 'The following File-Shares were found:\n\n' + sharelist;
  log_message( port:0, data:report );
}

exit( 0 );
