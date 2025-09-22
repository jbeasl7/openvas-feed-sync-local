# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807804");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-04-20 16:08:25 +0530 (Wed, 20 Apr 2016)");
  script_name("HP Support Assistant Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  HP Support Assistant Version Detection (Windows).

  The script logs in via smb, searches for 'HP Support Assistant' in the
  registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_hp_support_assistant_smb_login_detect.nasl",
                        "gsf/gb_hp_support_solution_framework_smb_login_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_exclude_keys("keys/is_gef");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

# nb: No need to run the detection in GEF at all because the new gsf/gb_hp_support_assistant_smb_login_detect.nasl
# and gsf/gb_hp_support_solution_framework_smb_login_detect.nasl should run instead
if( get_kb_item( "keys/is_gef" ) )
  exit( 0 );

if( ! registry_key_exists( key:"SOFTWARE\Hewlett-Packard" ) )
{
  if( ! registry_key_exists( key:"SOFTWARE\Wow6432Node\Hewlett-Packard" ) ) {
    exit( 0 );
  }
}

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

##Key based on architecture
if( "x86" >< os_arch )
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

else if( "x64" >< os_arch )
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

else
  exit( 0 );

foreach item ( registry_enum_keys( key:key ) ) {
  hpName = registry_get_sz( key:key + item, item:"DisplayName" );

  if( "HP Support Assistant" >< hpName ) {
    hpVer = registry_get_sz( key:key + item, item:"DisplayVersion" );

    if( hpVer ) {
      hpPath = registry_get_sz( key:key + item, item:"InstallLocation" );
      if( ! hpPath )
        hpPath = "Could not find the install location from registry";

      set_kb_item( name:"hp/support_assistant/detected", value:TRUE );

      cpe = build_cpe( value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:support_assistant:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:hp:support_assistant";

      register_product( cpe:cpe, location:hpPath );

      log_message( data: build_detection_report( app: "HP Support Assistant",
                                                 version: hpVer,
                                                 install: hpPath,
                                                 cpe: cpe,
                                                 concluded: hpVer ) );
    }
  }

  if( "HP Support Solutions Framework" >< hpName ) {
    hpVer = registry_get_sz( key:key + item, item:"DisplayVersion" );

    if( hpVer ) {
      hpPath = registry_get_sz( key:key + item, item:"InstallLocation" );
      if( ! hpPath )
        hpPath = "Could not find the install location from registry";

      set_kb_item( name:"hp/support_solutions_framework/detected", value:TRUE );

      cpe = build_cpe( value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:support_solution_framework:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:hp:support_solution_framework";

      register_product( cpe:cpe, location:hpPath );

      log_message( data: build_detection_report( app: "HP Support Assistant Framework",
                                                 version: hpVer,
                                                 install: hpPath,
                                                 cpe: cpe,
                                                 concluded: hpVer ) );
    }
  }
}
