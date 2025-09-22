# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112378");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-12 17:55:14 +0200 (Wed, 12 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2012-1193");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor < 3.5 Ghost Domain Names Attack");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:'The resolver in PowerDNS Recursor (aka pdns_recursor)
  3.3 overwrites cached server names and TTL values in NS records during the processing of
  a response to an A record query, which allows remote attackers to trigger continued resolvability
  of revoked domain names via a "ghost domain names" attack.');

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Recursor before version 3.5.");

  script_tag(name:"solution", value:"Update PowerDNS Recursor to version 3.5 or later.");

  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-April/102729.html");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-May/104173.html");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-May/104177.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:powerdns:recursor";

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"3.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
