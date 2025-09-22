# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105285");
  script_cve_id("CVE-2015-0713");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2024-03-01T14:37:10+0000");

  script_name("Cisco TelePresence Server Remote Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74638");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150513-tp");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to execute
arbitrary commands with root privileges in the context of the affected device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue is being tracked by Cisco Bug IDs CSCur15855, CSCur15842,
CSCul55968, CSCur15832, CSCur15825, CSCur15807, CSCur15850, CSCur15803, and CSCur08993.");

  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"Multiple Cisco TelePresence Products are prone to a remote command-
injection vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"3.1(1.98) for Hardware release, 4.1(1.79) for Virtual Machine");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-06-03 12:10:07 +0200 (Wed, 03 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_telepresence_server_detect.nasl");
  script_mandatory_keys("cisco_telepresence_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) ) {
  if( ! vers = get_kb_item( "cisco_telepresence_server/version" ) )
    exit( 0 );
}

if( ! model = get_kb_item( "cisco_telepresence_server/model" ) )
  exit( 0 );

if( model == "VM" )
{
  fix = '4.1.1.79';
  report_fix = '4.1(1.79)';
}
else
{
  fix = '3.1.1.98';
  report_fix = '3.1(1.98)';
}

report_vers = vers;

vers = str_replace( string:vers, find:"(", replace:"." );
vers = str_replace( string:vers, find:")", replace:"" );

if( version_is_less( version:vers, test_version: fix ) ) {
  report = 'Installed version: ' + report_vers + '\n' +
           'Fixed version:     ' + report_fix  + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
