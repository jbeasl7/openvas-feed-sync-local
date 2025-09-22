# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107315");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-04-26 14:36:37 +0200 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CCleaner Portable Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  # nb: CCleaner dependency was added so we don't detect a registry-based installation twice
  script_dependencies("gb_ccleaner_smb_login_detect.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("win/lsc/search_portable_apps");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login and WMI file search based detection of CCLeaner
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

fileList = powershell_wmi_file_search_version_query( file_name:"ccleaner", file_extension:"exe" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

# From gb_ccleaner_smb_login_detect.nasl to avoid a doubled detection of a registry-based installation.
detectedList = get_kb_list( "piriform/ccleaner/locations" );

foreach filePath( keys( fileList ) ) {

  # powershell_wmi_file_search_version_query returns the .exe filename so we're stripping it away
  # to keep the install location registration the same way like in gb_ccleaner_smb_login_detect.nasl
  location = ereg_replace( string:filePath, pattern:"\\ccleaner\.exe$", replace:"", icase:TRUE );

  if( detectedList && in_array( search:tolower( location ), array:detectedList ) )
    continue; # We already have detected this installation...

  vers = fileList[filePath];

  # Remove the third version component to match the official format (e.g., "6.39.11548" from "6.39.0.11548")
  # https://www.ccleaner.com/ccleaner/version-history
  if( vers && version_info = eregmatch( string:vers, pattern:"^([0-9]+\.[0-9]+\.)[0-9]+\.([0-9]+)" ) ) {
    version = version_info[1] + version_info[2];
    set_kb_item( name:"piriform/ccleaner/locations", value:tolower( location ) );

    # The portableapps.com installer is putting the 32bit version in App\CCleaner and the 64bit into App\CCLeaner64.
    # This is the only way to differ between 32bit and 64bit as we can't differ between 32 and 64bit based on the file information.
    if( "ccleaner64" >< location ) {
      cpe = "cpe:/a:piriform:ccleaner:x64:";
      set_kb_item( name:"piriform/ccleanerx64/detected", value:TRUE );
      set_kb_item( name:"piriform/ccleanerx64/smb-login/detected", value:TRUE );
    } else {
      cpe = "cpe:/a:piriform:ccleaner:";
      set_kb_item( name:"piriform/ccleaner/detected", value:TRUE );
      set_kb_item( name:"piriform/ccleaner/smb-login/detected", value:TRUE );
    }
    register_and_report_cpe( app:"CCleaner Portable", ver:version, concluded:vers + '\n\n', base:cpe, expr:"^([0-9.]+)", insloc:location, regPort:0, regService:"smb-login" );
  }
}

exit( 0 );
