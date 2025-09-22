# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107408");
  script_version("2024-08-01T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"creation_date", value:"2018-12-08 12:31:03 +0100 (Sat, 08 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("SolarWinds Orion Network Performance Monitor (NPM) Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of the SolarWinds Orion Network
  Performance Monitor (NPM).");

  exit(0);
}

include( "smb_nt.inc" );
include( "host_details.inc" );
include( "secpod_smb_func.inc" );

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list1 = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list1 = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list1 ) )
  exit( 0 );

foreach key1( key_list1 ) {
  foreach item1( registry_enum_keys( key:key1 ) ) {

    appName = registry_get_sz( key:key1 + item1, item:"DisplayName" );
    if( ! appName )
      continue;

    if( "SolarWinds Orion Network Performance Monitor"  >< appName ){
      set_kb_item( name:"solarwinds/orion/npm/smb/display_name", value:"SolarWinds Orion Network Performance Monitor (NPM)" );
      concluded  = 'Registry Key:   ' + key1 + item1 + '\n';
      concluded += 'DisplayName:    ' + appName + '\n';
      location = "unknown";
      version = "unknown";

      loc = registry_get_sz( key:key1 + item1, item:"InstallSource" );
      if( loc )
        location = loc;

      # DisplayName:    SolarWinds Orion Network Performance Monitor 2020.2.6
      # DisplayVersion: 120.2.50073.6
      # because of this the DisplayName takes precedence below to avoid a false version extraction.
      #
      # Older versions had the following:
      # DisplayName:    SolarWinds Orion Network Performance Monitor v12.4
      # DisplayVersion: 12.4.5200.0
      vers = eregmatch( pattern:"SolarWinds Orion Network Performance Monitor ([0-9.]+)", string:appName );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
      } else {
        if( vers = registry_get_sz( key:key1 + item1, item:"DisplayVersion" ) ) {
          version = vers;
          concluded += 'DisplayVersion: ' + vers + '\n';
        }
      }

      set_kb_item( name:"solarwinds/orion/npm/detected", value:TRUE );
      set_kb_item( name:"solarwinds/orion/npm/smb/detected", value:TRUE );
      set_kb_item( name:"solarwinds/orion/npm/smb/x86/version", value:version );
      set_kb_item( name:"solarwinds/orion/npm/smb/path", value:location );
      set_kb_item( name:"solarwinds/orion/npm/smb/concluded", value:concluded );

      exit( 0 );
    }

    if( "SolarWinds Platform" >< appName ){
      key_list2 = make_list( "SOFTWARE\Wow6432Node\SolarWinds\Orion\" );
      if( isnull( key_list2 ) )
        exit( 0 );

      foreach key2( key_list2 ) {
        foreach item2( registry_enum_keys( key:key2 ) ) {
          if( item2 == "NPM" ) {

            concluded  = "Registry Key:   " + key2 + item2 + '\n';
            location = "unknown";
            version = "unknown";

            appName2 = registry_get_sz( key:key2 + item2, item:"ProductDisplayName" );
            if( appName2 && appName2 == "SolarWinds Platform"){
            concluded += "DisplayName:    " + appName2 + " (NPM)" + '\n';
            set_kb_item( name:"solarwinds/orion/npm/smb/display_name", value:appName2 + " (NPM)" );
            }

            vers = registry_get_sz( key:key2 + item2, item:"Version" );
            if( vers ){
              concluded += 'DisplayVersion: ' + vers + '\n';
              if(match = eregmatch(string: vers, pattern: "([0-9]+)\.([0-9]+)\.([0-9]+)"))
              version = match[0];
            }

            loc = registry_get_sz( key:key2 + item2, item:"InstallDir" );
            if( loc )
              location = loc;

            set_kb_item( name:"solarwinds/orion/npm/detected", value:TRUE );
            set_kb_item( name:"solarwinds/orion/npm/smb/detected", value:TRUE );
            set_kb_item( name:"solarwinds/orion/npm/smb/x86/version", value:version );
            set_kb_item( name:"solarwinds/orion/npm/smb/path", value:location );
            set_kb_item( name:"solarwinds/orion/npm/smb/concluded", value:concluded );

            exit( 0 );
          }
        }
      }
    }
  }
}

exit( 0 );
