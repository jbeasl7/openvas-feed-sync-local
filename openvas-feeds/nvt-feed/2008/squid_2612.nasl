# SPDX-FileCopyrightText: 2008 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80017");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2007-1560");
  script_name("Squid < 2.6.STABLE12 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2007_1.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80017");

  script_tag(name:"summary", value:"A vulnerability in TRACE request processing has been reported in
  Squid.");

  script_tag(name:"impact", value:"This flaw can be exploited by an attacker to cause a denial of
  service (DoS).");

  script_tag(name:"solution", value:"Update to version 2.6 or later.");

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

if( egrep( pattern:"2\.([0-5]\.|6\.STABLE([0-9][^0-9]|1[01][^0-9]))", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );