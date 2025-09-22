# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801289");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_name("TortoiseSVN Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of TortoiseSVN.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include( "smb_nt.inc" );
include( "secpod_smb_func.inc" );
include( "cpe.inc" );
include( "host_details.inc" );

if( ! registry_key_exists( key:"SOFTWARE\TortoiseSVN\" ) ) {
  exit( 0 );
}

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch ) {
  exit( 0 );
}

# 32bit app can't be installed on 64bit OS. The 32bit installer on a
# 64bit OS will just quit the installation process.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) ) {
  exit( 0 );
}

foreach item( registry_enum_keys( key:key ) ) {
  appName = registry_get_sz( key:key + item, item:"DisplayName" );
  if( ! appName || appName !~ "TortoiseSVN" )
    continue;

  concluded  = "Registry Key:   " + key + item + '\n';
  concluded += "DisplayName:    " + appName;
  location = "unknown";
  version = "unknown";

  if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
    regvers = vers;
    concluded += '\nDIsplayVersion: ' + regvers;
    versionmatch = eregmatch( string:appName, pattern:"([0-9]+\.[0-9]+\.[0-9])+" );
    version = versionmatch[0];
    # nb. Done to match versions mentioned in advisories.
    concluded += '\nVersion: ' + version + ' ' + 'extracted from registry key-value "DisplayName"';
  }

  loc = registry_get_sz( key:key + item, item:"InstallLocation" );
  if( loc )
    location = loc;

  set_kb_item( name:"tortoisesvn/detected", value:TRUE );

  if( "64" >< os_arch ) {
    cpe_old = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tigris:tortoisesvn:x64:" );
    if( ! cpe_old )
      cpe_old = "cpe:/a:tigris:tortoisesvn:x64";
    register_product( cpe:cpe_old, location:location, port:0, service:"smb-login" );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tortoisesvn:tortoisesvn:x64:" );
    if( ! cpe )
      cpe = "cpe:/a:tortoisesvn:tortoisesvn:x64";
    register_product( cpe:cpe, location:location, port:0, service:"smb-login" );

  } else {
    cpe_old = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tigris:tortoisesvn:" );
    if( ! cpe_old )
      cpe_old = "cpe:/a:tigris:tortoisesvn";
    register_product( cpe:cpe_old, location:location, port:0, service:"smb-login" );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tortoisesvn:tortoisesvn:" );
    if( ! cpe )
      cpe = "cpe:/a:tortoisesvn:tortoisesvn";
    register_product( cpe:cpe, location:location, port:0, service:"smb-login" );

  }

  log_message( data:build_detection_report( app:appName, version:version, install:location, cpe:cpe, concluded:concluded ),
               port:0 );
  exit( 0 );
}

exit( 0 );
