# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107460");
  script_version("2024-12-13T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-12-13 05:05:32 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"creation_date", value:"2019-01-18 14:33:03 +0100 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Horner Automation/APG Cscape Programming Software Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://hornerautomation.com/cscape-software/");

  script_tag(name:"summary", value:"SMB login-based detection of Horner Automation (formerly Horner
  APG) Cscape Programming software.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    appName = registry_get_sz( key:key + item, item:"DisplayName" );

    if( ! appName || appName !~ "Cscape [0-9.]+" )
      continue;

    concluded  = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + appName;
    location = "unknown";
    version = "unknown";

    regversion = registry_get_sz( key:key + item, item:"DisplayVersion" );

    # Vendor uses an x.yy.zzz version scheme. New releases have to be installed
    # and checked for related version information in registry
    #
    # Version 9.80 SP4   has Fileversion 9.80.100.5
    # Version 9.90 SP3.5 has Fileversion 9.90.104.4
    # Version 9.90 SP4   has Fileversion 9.90.178.5
    # Version 9.90 SP5   has Fileversion 9.90.196.6
    # Version 9.90 SP6   has Fileversion 9.90.287.7
    # Version 9.90 SP7   has Fileversion 9.90.364.8
    # Version 9.90 SP7.1 has Fileversion 9.90.365.8
    # Version 9.90 SP8   has Fileversion 9.90.469.9
    # Version 9.90 SP9   has Fileversion 9.90.501.10
    # Version 9.90 SP10  has Fileversion 9.90.539.11
    # Version 9.90 SP11  has Fileversion 9.90.561.12
    # Version 10.0       has Fileversion 10.0.363.1
    # Version 10.0 SP1   has Fileversion 10.0.415.2
    #
    # registry item 'DisplayVersion' does not always provide SP value information.
    # Therefore we check the fileversion below and represent it in correct format.

    if( regversion )
      concluded += '\nDisplayVersion: ' + regversion;

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc ) {
      location = loc;

      file = "Cscape.exe";
      vers = fetch_file_version( sysPath:location, file_name:file );
      if( vers && vers =~ "^[0-9.]{3,}" ) {
        vers2 = eregmatch( string:vers, pattern:"^([0-9]+\.[0-9]+\.[0-9]{3})" );
        if( vers2[1] ) {
          version = vers2[1];
          concluded += '\nFileversion:    ' + version + ' fetched from ' + location + file;
        }
      }
    }

    set_kb_item( name:"hornerautomation/cscape/detected", value:TRUE );
    set_kb_item( name:"hornerautomation/cscape/smb-login/detected", value:TRUE );

    register_and_report_cpe( app:"Horner Automation/APG " + appName, ver:version, concluded:concluded,
                             base:"cpe:/a:hornerautomation:cscape:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
