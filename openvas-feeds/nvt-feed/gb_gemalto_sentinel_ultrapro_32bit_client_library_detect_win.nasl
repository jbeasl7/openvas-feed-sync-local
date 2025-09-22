# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107630");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-03-30 13:50:35 +0100 (Sat, 30 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Gemalto Sentinel UltraPro 32bit Client Library Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "gb_gemalto_sentinel_protection_installer_detect_win.nasl", "lsc_options.nasl");
  script_mandatory_keys("gemalto/sentinel_protection_installer/win/detected", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of the Gemalto Sentinel UltraPro
  32bit Client Library.");

  script_xref(name:"URL", value:"https://sentinel.gemalto.com/");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("powershell_func.inc");
include("list_array_func.inc");
include("cpe.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

fileList = powershell_wmi_file_search_query( dir_path_like:"%program files%", file_name:"ux32w", file_extension:"dll" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

loc = fileList[0];
if( loc ) {
  split = split( loc, sep:"\" );
  location = ereg_replace( string:loc, pattern:split[max_index( split ) - 1], replace:"" );
}

version = fetch_file_version( sysPath:location, file_name:"ux32w.dll" );

set_kb_item( name:"gemalto/sentinel_ultrapro_32bit_client_library/win/detected", value:TRUE );

register_and_report_cpe( app:"Gemalto Sentinel UltraPro 32bit Client Library", ver:version, concluded:loc,
                         base:"cpe:/a:gemalto:sentinel_ultrapro_32bit_client_library:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0 );
exit( 0 );
