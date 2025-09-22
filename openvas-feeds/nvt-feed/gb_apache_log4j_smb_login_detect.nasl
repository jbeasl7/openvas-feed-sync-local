# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118288");
  script_version("2025-02-21T15:40:05+0000");
  script_tag(name:"last_modification", value:"2025-02-21 15:40:05 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2021-12-15 14:19:09 +0100 (Wed, 15 Dec 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Log4j Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login-based detection of Apache Log4j.");

  script_tag(name:"vuldetect", value:"To get the product version, the script logs in via SMB and
  searches for the Log4j JAR file on the filesystem.");

  script_tag(name:"qod_type", value:"executable_version");

  script_timeout(900); # nb: File search might take a while...

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");
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

type = "(JAR file)";
port = kb_smb_transport();

# Search each drive for vulnerable log4j files
foreach drive( split( drives, keep:FALSE ) ) {

  # nb: For some unknown reason the powershell command above might return a directory letter with
  # trailing newlines / spaces so we need to strip them off.
  if( ! drive = ereg_replace( string:drive, pattern:"\s+", replace:"" ) )
    continue;

  if( p_version_check == TRUE )
    cmd = 'Get-childitem log4j-*.jar -Path ' + drive + ' -recurse -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';
  else
    cmd = 'Get-childitem ' + drive + '\\log4j-*.jar -file -Recurse -OutBuffer 1000 -Erroraction \'silentlycontinue\' | % { $_.FullName } | ft -HideTableHeaders';

  if( ! files = powershell_cmd( cmd:cmd ) )
    continue;

  foreach file( split( files, keep:FALSE ) ) {

    # nb: We only want to match something like:
    # log4j-core-2.11.1.jar
    # log4j-1.2-1.2.17.jar
    # log4j-1.2.jar
    # log4j-1.2.17.jar
    # log4j-1.2.x.jar
    # but not:
    # log4j-core-2.14.1-sources.jar
    # log4j-core-2.14.1-javadoc.jar
    # log4j-web-2.14.1.jar
    # log4j-to-slf4j-2.14.1.jar
    #
    if( file =~ "\\log4j(-core)?(-[0-9.x-]+)?\.jar$" ) {

      version = "unknown";
      concluded = ""; # nb: Just overwriting a possible previously defined string

      # nb: As some of the files examples above contains e.g. 1.2-1.2.17 and we only want to catch
      # the last version so we're using a more strict regex pattern here enforcing a version having
      # three number parts.
      vers = eregmatch( string:file, pattern:"\log4j.*-([0-9.x]+)\.jar", icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        concluded = vers[0];
      }

      set_kb_item( name:"apache/log4j/detected", value:TRUE );
      set_kb_item( name:"apache/log4j/smb-login/detected", value:TRUE );
      set_kb_item( name:"apache/log4j/smb-login/" + port + "/installs", value:"0#---#" + file + "#---#" + version + "#---#" + concluded + "#---#" + type );
    }
  }
}

exit( 0 );
