# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805941");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-08-04 17:21:51 +0530 (Tue, 04 Aug 2015)");
  script_name("Node.js Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of Node.js");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_exclude_keys("keys/is_gef");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

# nb: No need to run the detection in GSF at all because the new gsf/gb_nodejs_smb_login_detect.nasl should run instead
if ( get_kb_item( "keys/is_gef" ) )
  exit( 0 );

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch ){
  exit( 0 );
}

if( "x86" >< os_arch ){
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

else if( "x64" >< os_arch )
{
  key_list =  make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) ) {
  exit( 0 );
}


foreach key ( key_list ) {
  foreach item ( registry_enum_keys( key:key ) ) {

    appName = registry_get_sz( key:key + item, item:"DisplayName" );

    if( ! appName || appName !~ "Node\.js" )
      continue;

    concluded = "Registry Key:    HKEY_LOCAL_MACHINE\" + key + item;
    concluded += '\nDisplay Name:    ' + appName;
    install_location = "unknown";
    version = "unknown";

    if( loc = registry_get_sz( key:key + item, item:"InstallLocation" ) )
      install_location = loc;

    if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
      version = vers;
      concluded += '\nDisplay Version: ' + version;
    }

    set_kb_item( name:"nodejs/detected", value:TRUE );
    set_kb_item( name:"nodejs/smb-login/detected", value:TRUE );

    register_and_report_cpe( app:"Node.js", ver:version, concluded:concluded,
                             base:"cpe:/a:nodejs:node.js:", expr:"^([0-9.]+)",
                             insloc:install_location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}

exit( 0 );
