# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112376");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-12 17:43:21 +0200 (Wed, 12 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2015-5311");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Security Advisory 2015-03: Packet parsing bug can lead to crashes");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"A bug was found using afl-fuzz in our packet parsing code.
  This bug, when exploited, causes an assertion error and consequent termination of the pdns_server process,
  causing a Denial of Service.

  When the PowerDNS Authoritative Server is run inside the guardian (--guardian), or inside a supervisor like
  supervisord or systemd, it will be automatically restarted, limiting the impact to a somewhat degraded service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server 3.4.4 up to and including 3.4.6 are affected.");

  script_tag(name:"solution", value:"Update PowerDNS Authoritative Server to version 3.4.7.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2015-03/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:powerdns:authoritative_server";

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range( version:version, test_version:"3.4.4", test_version2:"3.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.7" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
