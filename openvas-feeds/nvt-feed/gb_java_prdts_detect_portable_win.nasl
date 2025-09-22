# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107318");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-04-25 17:33:28 +0200 (Wed, 25 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Java Portable Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  # nb: Java Products dependency was added so we don't detect a registry-based installation twice
  script_dependencies("gb_java_prdts_detect_win.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("win/lsc/search_portable_apps");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"SMB login and WMI file search based detection of Java
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
include("version_func.inc");

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

fileList = powershell_wmi_file_search_version_query( file_name:"java", file_extension:"exe" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

# From gb_java_prdts_detect_win.nasl to avoid a doubled detection of a registry-based installation.
detectedList = get_kb_list( "Java/Win/InstallLocations" );

foreach filePath( keys( fileList ) ) {

  # powershell_wmi_file_search_version_query returns the .exe filename so we're stripping it away
  # to keep the install location registration the same way like in gb_java_prdts_detect_win.nasl
  location = filePath - "\java.exe";
  if( detectedList && in_array( search:tolower( location ), array:detectedList ) )
    continue; # We already have detected this installation...

  vers = fileList[filePath];

  # Version of the java.exe file is something like 8.0.1710.11
  # so we need to catch only the first three parts of the version.
  if( vers && version = eregmatch( string:vers, pattern:"^([0-9]+\.[0-9]+\.[0-9]{1,3})" ) ) {

    set_kb_item( name:"Java/Win/InstallLocations", value:tolower( location ) );

    # For correct determination of the product we need to add "1." as leading number to the detected version number
    vers = "1." + version[1];

    set_kb_item( name:"Sun/Java/JRE/Win/Ver", value:vers );
    set_kb_item( name:"Sun/Java/JDK_or_JRE/Win/installed", value:TRUE );
    set_kb_item( name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE );

    # The portableapps.com installer is putting the 32bit version in CommonFiles\Java and the 64bit into CommonFiles\Java64.
    # This is the only way to differ between 32bit and 64bit as we can't differ between 32 and 64bit based on the file information.
    if( "java64" >< location ) {

      set_kb_item( name:"Sun/Java64/JRE64/Win/Ver", value:vers );

      if( version_is_less( version:vers, test_version:"1.4.2.38" ) ||
          version_in_range( version:vers, test_version:"1.5", test_version2:"1.5.0.33" ) ||
          version_in_range( version:vers, test_version:"1.6", test_version2:"1.6.0.18" ) ){
        # nb: Before Oracles acquisition of Sun
        java_name = "Sun Java JRE 64-bit";
        cpe = "cpe:/a:sun:jre:x64:";
      } else {
        # nb: After Oracles acquisition of Sun
        java_name = "Oracle Java JRE 64-bit";
        cpe = "cpe:/a:oracle:jre:x64:";
      }
    } else {
      if( version_is_less( version:vers, test_version:"1.4.2.38" ) ||
          version_in_range( version:vers, test_version:"1.5", test_version2:"1.5.0.33" ) ||
          version_in_range( version:vers, test_version:"1.6", test_version2:"1.6.0.18" ) ) {
        # nb: Before Oracles acquisition of Sun
        java_name = "Sun Java JRE 32-bit";
        cpe = "cpe:/a:sun:jre:";
      } else {
        # nb: After Oracles acquisition of Sun
        java_name = "Oracle Java JRE 32-bit";
        cpe = "cpe:/a:oracle:jre:";
      }
    }
    register_and_report_cpe( app:java_name + " Portable", ver:vers, concluded:vers, base:cpe, expr:"^([:a-z0-9._]+)", insloc:location, regPort:0, regService:"smb-login" );
  }
}

exit( 0 );
