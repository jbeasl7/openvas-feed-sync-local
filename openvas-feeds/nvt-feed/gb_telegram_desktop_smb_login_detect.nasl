# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814305");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-11-05 16:30:44 +0530 (Mon, 05 Nov 2018)");

  script_tag(name:"qod_type", value:"registry");

  script_name("Telegram Desktop Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login and WMI file search based detection of Telegram
  Desktop.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_xref(name:"URL", value:"https://desktop.telegram.org/");

  exit(0);
}

include("powershell_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

fileList = powershell_wmi_file_search_version_query( file_name:"Telegram", file_extension:"exe" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

foreach filePath( keys( fileList ) )
{
  location = ereg_replace( string:filePath, pattern:"\\telegram\.exe$", replace:"", icase:TRUE );
  if( "\tupdates\temp" >!< location )
  {
    telPath = location;
    vers = fileList[filePath];
    if( vers )
    {
      version = eregmatch( string:vers, pattern:"^([0-9.]+)");
      if( version[1] )
      {
        set_kb_item( name:"telegram/desktop/detected", value:TRUE );
        register_and_report_cpe( app:"Telegram Desktop", ver:version[1],
                                 concluded:version[0], base:"cpe:/a:telegram:tdesktop:",
                                 expr:"([0-9.]+)", insloc:location );
      }
    }
  }
}

exit(0);
