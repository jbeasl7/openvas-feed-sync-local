# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107446");
  script_version("2025-04-22T10:32:18+0000");
  script_tag(name:"last_modification", value:"2025-04-22 10:32:18 +0000 (Tue, 22 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-01-10 14:42:01 +0100 (Thu, 10 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Schneider Electric Zelio Soft 2 Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_schneider_zelio_soft_smb_login_wsc_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_exclude_keys("keys/is_gef");

  script_tag(name:"summary", value:"SMB login-based detection of Schneider Electric Zelio Soft 2.");

  script_xref(name:"URL", value:"https://www.se.com/us/en/product-range/542-zelio-soft");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include( "smb_nt.inc" );
include( "cpe.inc" );
include( "host_details.inc" );
include( "secpod_smb_func.inc" );

# nb: No need to run the detection in GEF at all because the new gsf/gb_schneider_zelio_soft_smb_login_wsc_detect.nasl should run instead
if( get_kb_item( "keys/is_gef" ) )
  exit( 0 );

if( ! os_arch = get_kb_item( "SMB/Windows/Arch" ) )
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

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! app_name || app_name !~ "Zelio[ ]?Soft" )
      continue;

    concluded  = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";

    # We need to fetch the fileversion to report the full version referenced to in advisories
    if( loc = registry_get_sz( key:key + item, item:"InstallLocation" ) ) {
      location = loc;
      file = "Zelio2.exe";
      vers = fetch_file_version( sysPath:location, file_name:file );
      if( vers && vers =~ "^[0-9.]{3,}" ) {
        version = vers;
        concluded += '\nFileversion:    ' + vers + ' fetched from ' + location + "\" + file;
      }
    }

    if( disp_vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) )
      concluded += '\nDisplayVersion: ' + disp_vers;

    set_kb_item( name:"schneider/zelio_soft2/detected", value:TRUE );
    set_kb_item( name:"schneider/zelio_soft2/smb-login/detected", value:TRUE );

    register_and_report_cpe( app:"Schneider Electric " + app_name, ver:version, concluded:concluded,
                             base:"cpe:/a:schneider-electric:zelio_soft2:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
