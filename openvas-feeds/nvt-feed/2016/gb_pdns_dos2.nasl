# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:authoritative_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106238");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-09-12 10:44:19 +0700 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");
  script_cve_id("CVE-2016-5426", "CVE-2016-5427");
  script_name("PowerDNS Authoritative Server DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-01/");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to two denial of service
  (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Two issues have been found in PowerDNS Authoritative Server allowing a
  remote, unauthenticated attacker to cause an abnormal load on the PowerDNS backend by sending crafted DNS
  queries, which might result in a partial denial of service if the backend becomes overloaded. SQL backends for
  example are particularly vulnerable to this kind of unexpected load if they have not been dimensioned for it.
  The first issue is based on the fact that PowerDNS Authoritative Server accepts queries with a qname's length
  larger than 255 bytes (CVE-2016-5426). The second issue is based on the fact that PowerDNS Authoritative Server
  does not properly handle dot inside labels (CVE-2016-5427).");

  script_tag(name:"impact", value:"A remote attacker may cause a partial DoS condition.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server 3.4.9 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 3.4.10 or later");

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

if( version_is_less( version:version, test_version:"3.4.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.10" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
