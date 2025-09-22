# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800584");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-1196", "CVE-2009-0791");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.4.0 Multiple DoS Vulnerabilities (Jun 2009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) service is prone to multiple
  denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2009-1196: A use after free error within the directory services functionality in the
  scheduler.

  - CVE-2009-0791: Integer overflow errors within the 'pdftops' filter while processing specially
  crafted PDF file.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code and can cause denial of service.");

  script_tag(name:"affected", value:"CUPS versions prior to 1.4.0.");

  script_tag(name:"solution", value:"Update to version 1.4.0 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35340");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35195");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1083.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jun/1022327.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
