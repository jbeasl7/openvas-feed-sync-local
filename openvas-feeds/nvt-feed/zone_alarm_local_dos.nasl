# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14726");
  script_version("2024-07-23T05:05:30+0000");
  script_cve_id("CVE-2004-2713");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"9761");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_name("ZoneAlarm Pro Local DoS Vulnerability (CVE-2004-2713)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"ZoneAlarm Pro is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"To exploit this flaw, an attacker would need to temper with the
  files located in  %windir%/Internet Logs. An attacker may modify them and prevent ZoneAlarm to
  start up properly.");

  script_tag(name:"solution", value:"Update to the latest version of this software.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) ) exit( 0 );

foreach item( registry_enum_keys( key:key ) ) {

  name = registry_get_sz( key:key + item, item:"DisplayName" );

  if( "ZoneAlarm Pro" >< name ) {

    version = registry_get_sz( key:key + item, item:"DisplayVersion" );
    if( version ) {

      set_kb_item( name:"zonealarm/version", value:version );

      register_and_report_cpe( app:"ZoneAlarm Pro", ver:version, concluded:version, base:"cpe:/a:zonelabs:zonealarm:", expr:"^([0-9.]+)" );

      if( ereg( pattern:"[1-4]\.|5\.0\.|5\.1\.", string:version ) ) {
        security_message( port:0, data:"The target host was found to be vulnerable." );
        exit( 0 );
      }
    }
  }
}

exit( 0 );
