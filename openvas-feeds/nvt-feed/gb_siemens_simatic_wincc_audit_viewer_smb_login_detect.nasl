# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107574");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-02-16 10:09:25 +0100 (Sat, 16 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Siemens SIMATIC WinCC/Audit Viewer Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_siemens_simatic_wincc_audit_viewer_smb_login_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  # nb: Don't add a "script_exclude_keys" with "win/lsc/disable_wmi_search" as the detection is also
  # partly working based on the registry.
  script_exclude_keys("keys/is_gef");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://support.industry.siemens.com/cs/document/22180683/audit-viewer?dti=0&lc=en-US");

  script_tag(name:"summary", value:"SMB login-based detection of Siemens SIMATIC WINCC
  Audit/Viewer.");

  script_tag(name:"qod_type", value:"registry");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

# nb: No need to run the detection in GEF at all because the new gsf/gb_siemens_simatic_wincc_audit_viewer_smb_login_detect.nasl should run instead
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

foreach key ( key_list ) {
  foreach item ( registry_enum_keys( key:key ) ) {

    display_name = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! display_name || display_name !~ "SIMATIC WinCC/Audit Viewer [0-9A-Z]+" )
      continue;

    concluded = display_name;
    install_location = "unknown";

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc )
      install_location = loc;

    if( ! display_version = registry_get_sz( key:key + item, item:"DisplayVersion" ) )
      display_version = "unknown";

    set_kb_item( name:"siemens/simatic_wincc_audit_viewer/detected", value:TRUE );
    set_kb_item( name:"siemens/simatic_wincc_audit_viewer/smb-login/detected", value:TRUE );

    register_and_report_cpe( app:"Siemens AG " + display_name, ver:display_version, concluded:concluded,
                             base:"cpe:/a:siemens:simatic_wincc_audit_viewer:", expr:"^([0-9.]+)",
                             insloc:install_location, regService:"smb-login", regPort:0 );
    exit( 0 );
  }
}
exit( 0 );
