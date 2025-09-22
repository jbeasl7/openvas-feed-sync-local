# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800473");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0639");
  script_name("Squid HTCP Packets Processing DoS Vulnerability (SQUID-2010:2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0371");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38212");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2010_2.txt");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Feb/1023587.html");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v2/2.7/changesets/12600.patch");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v3/3.0/changesets/3.0-ADV-2010_2.patch");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash an
  affected server, creating a denial of service condition.");

  script_tag(name:"affected", value:"Squid version 2.x and 3.0 through 3.0.STABLE23.");

  script_tag(name:"insight", value:"The flaw is due to error in 'htcpHandleTstRequest()' function in
  'htcp.c', when processing malformed HTCP (Hypertext Caching Protocol) packets.");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Apply the patches from the references or update to version
  3.0.STABLE24 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers =~ "^2\." || version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.STABLE23" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.STABLE24" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );