# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:miniupnp_project:miniupnpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103657");
  script_cve_id("CVE-2013-0229", "CVE-2013-0230", "CVE-2013-1461", "CVE-2013-1462");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-02-06 14:48:10 +0100 (Wed, 06 Feb 2013)");
  script_version("2023-10-27T16:11:32+0000");
  script_name("MiniUPnP < 1.4 Multiple DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_miniupnp_detect_tcp.nasl", "gb_miniupnp_detect_udp.nasl");
  script_mandatory_keys("miniupnp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57608");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"MiniUPnP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"affected", value:"MiniUPnP versions prior to 1.4 are vulnerable.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to cause DoS conditions.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"1.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.4" );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
