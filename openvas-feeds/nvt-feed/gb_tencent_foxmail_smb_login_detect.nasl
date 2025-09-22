# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800219");
  script_version("2025-02-21T15:40:05+0000");
  script_tag(name:"last_modification", value:"2025-02-21 15:40:05 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Tencent FoxMail Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Tencent FoxMail.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("list_array_func.inc");

foreach keypart( make_list_unique( "Foxmail_is1", "Foxmail",
                   registry_enum_keys( key: "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ),
                   registry_enum_keys( key: "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ) ) ) {

  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + keypart;
  if( ! registry_key_exists( key: key ) ) {
    key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + keypart;
    if( ! registry_key_exists( key: key ) )
      continue;
  }

  name = registry_get_sz( key: key, item: "DisplayName" );
  if( "Foxmail" >!< name )
    continue;
  set_kb_item( name: "foxmail/detected", value: TRUE );

  concluded = "Registry Key:   " + key;
  concluded += '\nDisplayName:    ' + name;

  version = "unknown";

  vers = registry_get_sz( key: key, item: "DisplayVersion" );

  loc = registry_get_sz( key: key, item: "UninstallString" );

  if( vers ) {
    version = vers;
    concluded += '\nDisplayVersion: ' + version;
  }

  if( ! isnull( loc ) ){
    loc = ereg_replace( pattern: "(uninst(all)?\.exe)", string: loc, replace: "", icase: TRUE );

    if( version == "unknown" ) {
      vers = fetch_file_version( sysPath: loc, file_name: "Foxmail.exe" );
      if( vers ) {
        version = vers;
        concluded += '\nVersion: ' + version + " from file " + loc + "Foxmail.exe";
      }
    }
  }
  cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tencent:foxmail:" );
  if( ! cpe )
    cpe = "cpe:/a:tencent:foxmail";

  register_product( cpe: cpe, location: loc, service: "smb-login", port: 0 );


  report = build_detection_report( app: "Tencent Foxmail",
                                   version: version,
                                   install: loc,
                                   cpe: cpe,
                                   concluded: concluded );
  log_message( port: 0, data: report );
  break;
}

exit( 0 );
