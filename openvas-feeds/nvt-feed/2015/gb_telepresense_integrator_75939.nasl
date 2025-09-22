# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105351");
  script_version("2025-09-09T14:09:45+0000");
  script_cve_id("CVE-2015-4271");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-09-11 11:38:35 +0200 (Fri, 11 Sep 2015)");
  script_name("Cisco TelePresence Integrator C Series Authentication Bypass Vulnerability (CSCuv00604)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_telepresence_snmp_detect.nasl", "gb_cisco_telepresence_ftp_detect.nasl");
  script_mandatory_keys("cisco/telepresence/typ", "cisco/telepresence/version");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75939");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv00604");

  script_tag(name:"summary", value:"Cisco TelePresence Integrator C Series devices running TC
  Software are prone to an authentication-bypass vulnerability because it fails to sufficiently
  sanitize the user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass the authentication
  mechanism on an affected device. This may lead to further attacks.");

  script_tag(name:"insight", value:"A vulnerability in Cisco TelePresence Integrator C Series could
  allow an unauthenticated, remote attacker to bypass authentication.

  The vulnerability is due to insufficient validation of user-supplied values. An attacker could
  exploit this vulnerability by sending multiple request parameters to an affected device.

  This issue is tracked by Cisco Bug ID CSCuv00604");

  script_tag(name:"affected", value:"Cisco TelePresence Integrator C Series devices running TC
  Software prior to versions 7.3.4.");

  script_tag(name:"solution", value:"Update to version 7.3.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) )
  exit( 0 );

if( ! typ = get_kb_item( "cisco/telepresence/typ" ) )
  exit( 0 );

# Integrator C Series -> http://www.cisco.com/c/en/us/support/collaboration-endpoints/telepresence-integrator-c-series/tsd-products-support-series-home.html
if( typ !~ "C(9|6|4|2)0" )
  exit( 99 );

version = eregmatch( pattern:"TC([0-9]+\.[0-9]+\.[0-9]+)", string:vers, icase:TRUE );
if( isnull( version[1] ) )
  exit( 0 );

vers = version[1];

if( vers !~ "^7\." )
  exit( 99 );

if( version_is_less( version:vers, test_version:"7.3.4" ) ) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     7.3.4';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
