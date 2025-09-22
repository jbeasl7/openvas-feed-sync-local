# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103233");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-30 14:29:55 +0200 (Tue, 30 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3205");
  script_name("Squid Gopher Remote Buffer Overflow Vulnerability (SQUID-2011:3)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49356");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2011_3.txt");

  script_tag(name:"summary", value:"Squid is prone remote buffer-overflow vulnerability affects the
  Gopher-to-HTML functionality.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with the
  privileges of the vulnerable application. Failed exploit attempts will
  result in a denial-of-service condition.");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3.2.0", test_version2:"3.2.0.10" ) ||
    version_is_less( version:vers, test_version:"3.1.15" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.15/3.2.0.11" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
