# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:authoritative_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103383");
  script_cve_id("CVE-2012-0206");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2025-09-05T15:40:40+0000");
  script_name("PowerDNS Authoritative Server Remote DoS Vulnerability (Jan 2012)");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-01-11 10:33:14 +0100 (Wed, 11 Jan 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51355");
  script_xref(name:"URL", value:"http://wiki.powerdns.com/trac/changeset/2331");
  script_xref(name:"URL", value:"http://mailman.powerdns.com/pipermail/pdns-users/2012-January/008457.html");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to cause the
  application to fall into an endless packet loop with other DNS
  servers, denying service to legitimate users.");
  script_tag(name:"solution", value:"The vendor has released a patch. Please see the references for
  details.");
  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to a remote denial of
  service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_equal( version:version, test_version:"2.9.22.5" ) ||
    version_is_equal( version:version, test_version:"2.9.22.6" ) ) {
  exit( 0 );
}

if( version_is_less( version:version, test_version:"3.0.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.0.1" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
