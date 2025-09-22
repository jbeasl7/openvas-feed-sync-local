# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113871");
  script_version("2025-02-21T15:40:05+0000");
  script_tag(name:"last_modification", value:"2025-02-21 15:40:05 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2022-04-05 08:02:35 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Spring Framework Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login-based detection of the VMware Spring Framework (and
  its components).");

  script_tag(name:"vuldetect", value:"To get the product version, the script logs in via SMB and
  searches for the VMware Spring Framework JAR files on the filesystem.");

  script_tag(name:"qod_type", value:"executable_version");

  script_timeout(900); # nb: File search might take a while...

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");
include("spring_prds.inc");
include("list_array_func.inc");
include("powershell_func.inc");

if( wmi_is_file_search_disabled() )
  exit( 0 );

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) )
  exit( 0 );

# Run powershell commands based on version
powershell_version = 'get-host | select-object version | ft -HideTableHeaders';
p_version = powershell_cmd( cmd:powershell_version );
p_version = ereg_replace( string:p_version, pattern:"\s+", replace:"" );
p_version_check = version_is_less( version:p_version, test_version:"3.0" );

if( p_version_check == TRUE )
  cmd = 'Get-WMIObject -Class Win32_logicaldisk -Filter \\\"DriveType=\'3\'\\\" | select DeviceID | ft -HideTableHeaders';
else
  cmd = 'Get-CimInstance -Class Win32_logicaldisk -Filter \\\"DriveType=\'3\'\\\" | select DeviceID | ft -HideTableHeaders';

if( ! drives = powershell_cmd( cmd:cmd ) ) # Retrieve a list of drives to search
  exit( 0 );

if( ! comp_list = spring_framework_comp_list() )
  exit( 0 );

if( ! comp_pattern = list2or_regex( list:comp_list ) )
  exit( 0 );

port = kb_smb_transport();

foreach drive( split( drives, keep:FALSE ) ) {

  # nb: For some unknown reason the powershell command above might return a directory letter with
  # trailing newlines / spaces so we need to strip them off.
  if( ! drive = ereg_replace( string:drive, pattern:"\s+", replace:"" ) )
    continue;

  if( p_version_check == TRUE )
    cmd = 'Get-childitem spring-*.jar -Path ' + drive + ' -recurse -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';
  else
    cmd = 'Get-childitem ' + drive + '\\spring-*.jar -file -Recurse -OutBuffer 1000 -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';

  if( ! files = powershell_cmd( cmd:cmd ) )
    continue;

  foreach file( split( files, keep:FALSE ) ) {

    # Default names of files if downloaded are e.g.:
    #
    # spring-core-5.3.17.jar
    # spring-webflux-5.3.17.jar
    # spring-webflux-5.3.17.jar
    #
    # Included in e.g. Struts2:
    #
    # struts-2.3.37/lib/spring-core-3.0.5.RELEASE.jar

    # nb: This makes sure that we're only catching the files we want.
    comp = eregmatch( string:file, pattern:"\\spring-" + comp_pattern + "[-.].*\.jar$", icase:FALSE );
    if( ! comp[1] )
      continue;

    version   = "unknown";
    concluded = ""; # nb: Just overwriting a possible previously defined string
    component = comp[1];
    comp_key  = tolower( component );

    vers = eregmatch( string:file, pattern:"\\spring-" + comp_pattern + "-([0-9.x]+)(\.RELEASE)?\.jar$", icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      concluded = vers[0];
    }

    set_kb_item( name:"vmware/spring/framework/detected", value:TRUE );
    set_kb_item( name:"vmware/spring/framework/smb-login/detected", value:TRUE );

    set_kb_item( name:"vmware/spring/framework/" + comp_key + "/detected", value:TRUE );
    set_kb_item( name:"vmware/spring/framework/" + comp_key + "/smb-login/detected", value:TRUE );

    set_kb_item( name:"vmware/spring/framework/smb-login/" + port + "/installs", value:"0#---#" + file + "#---#" + version + "#---#" + concluded + "#---#" + component );
  }
}

exit( 0 );
