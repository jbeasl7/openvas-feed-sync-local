# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814314");
  script_version("2024-10-29T05:05:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:46 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2018-10-15 12:44:20 +0530 (Mon, 15 Oct 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Framemaker Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe Framemaker
  on Windows.

  The script logs in via smb, searches for Adobe Framemaker and gets the
  version from registry.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://www.adobe.com/pl/products/framemaker.html");

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

    # Adobe FrameMaker 2022
    app_name = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! app_name || app_name !~ "Adobe FrameMaker" )
      continue;
    rel = eregmatch(pattern:"Adobe FrameMaker ([0-9]+)", string:app_name);
    release = rel[1];

    concluded = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";

    if( loc = registry_get_sz( key:key + item, item:"InstallLocation" ) )
      location = loc;

    # 17.0.4.628 in Registry vs commonly used version in advisories 2022.0.4
    if( ver = registry_get_sz( key:key + item, item:"DisplayVersion" ) )  {
      concluded += '\nDisplayVersion: ' + ver;
      build = eregmatch( string:ver, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)" );
      if( build[1] ) {
        set_kb_item( name:"adobe/framemaker/build", value:build[1] );
        concluded += '\nBuild: ' + build[1];
      }
    }

    # 2022 + "." + 0 + . + 4
    version = release + "." + ver[3] + ver[4] + ver[5];

    set_kb_item( name:"adobe/framemaker/detected", value:TRUE );
    set_kb_item( name:"adobe/framemaker/smb-login/detected", value:TRUE );

    register_and_report_cpe( app:"Adobe FrameMaker " + release, ver:version, concluded:concluded,
                             base:"cpe:/a:adobe:framemaker:", expr:"^([0-9.]+)",
                             insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );

