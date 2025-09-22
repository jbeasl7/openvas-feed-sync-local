# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114004");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-04-24 15:34:42 +0200 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Opera Portable Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  # nb: Opera dependency was added so we don't detect a registry-based installation twice
  script_dependencies("secpod_opera_detection_win_900036.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("win/lsc/search_portable_apps");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login and WMI file search based detection of Opera
  Portable.");

  script_tag(name:"insight", value:"To enable the search for portable versions of this product you
  need to 'Enable Detection of Portable Apps on Windows' in the 'Options for Local Security Checks'
  (OID: 1.3.6.1.4.1.25623.1.0.100509) of your scan config.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("powershell_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

fileList = powershell_wmi_file_search_version_query( file_name:"opera", file_extension:"exe" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

# From secpod_opera_detection_win_900036.nasl to avoid a doubled detection of a registry-based installation.
detectedList = get_kb_list( "Opera/Win/InstallLocations" );

foreach filePath( keys( fileList ) ) {

  # powershell_wmi_file_search_version_query returns the .exe filename so we're stripping it away
  # to keep the install location registration the same way like in secpod_opera_detection_win_900036.nasl
  location = ereg_replace( string:filePath, pattern:"\\opera\.exe$", replace:"", icase:TRUE );

  if( detectedList && in_array( search:tolower( location ), array:detectedList ) )
    continue; # We already have detected this installation...

  vers = fileList[filePath];

  # Version of the opera.exe file is something like 53.0.2907.68 or 52.0.2871.99
  # so we need to catch the first four parts of the version.
  if( vers && version = eregmatch( string:vers, pattern:"^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" ) ) {

    set_kb_item( name:"Opera/Win/InstallLocations", value:tolower( location ) );
    set_kb_item( name:"Opera/Win/Version", value:version[1] );

    # nb: Opera is only installed in the 32bit version
    cpe = "cpe:/a:opera:opera_browser:";
    register_and_report_cpe( app:"Opera Portable", ver:version[1], concluded:vers, base:cpe, expr:"^([0-9.]+)", insloc:location, regPort:0, regService:"smb-login" );
  }
}

exit( 0 );
