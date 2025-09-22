# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105609");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2015-6312");
  script_name("Cisco TelePresence Server Malformed STUN Packet Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160406-cts2");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by submitting malformed STUN packets to the device. If successful, the attacker could force the device to reload and drop all calls in the process.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to a failure to properly process malformed Session Traversal Utilities for NAT (STUN) packets.");

  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"A vulnerability in Cisco TelePresence Server devices running software version 3.1 could allow an unauthenticated, remote attacker to reload the device.");

  script_tag(name:"affected", value:"The following Cisco TelePresence Server devices running Cisco TelePresence Server software version 3.1 are vulnerable:
Cisco TelePresence Server 7010
Cisco TelePresence Server Mobility Services Engine (MSE) 8710
Cisco TelePresence Server on Multiparty Media 310
Cisco TelePresence Server on Multiparty Media 320
Cisco TelePresence Server on Virtual Machine (VM)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:11:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-04-18 15:50:01 +0200 (Mon, 18 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_telepresence_server_detect.nasl");
  script_mandatory_keys("cisco_telepresence_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "^3\.1" ) exit( 99 );

if( ! model = get_kb_item( "cisco_telepresence_server/model" ) ) exit( 0 );

if( model !~ '^7010$' && model !~ '^8710$' && model !~ 'Media 3(1|2)0' && model != "VM" ) exit( 99 );

fix = '4.2.4.18';
report_fix = '4.2(4.18)';
report_vers = vers;

vers = str_replace( string:vers, find:"(", replace:"." );
vers = str_replace( string:vers, find:")", replace:"" );

if( version_is_less( version:vers, test_version: fix ) )
{
  report = 'Installed version: ' + report_vers + '\n' +
           'Fixed version:     ' + report_fix  + '\n' +
           'Model:             ' + model       + '\n';

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
