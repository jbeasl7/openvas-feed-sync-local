# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100687");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1748", "CVE-2010-0540");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.4.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2010-1748: The cgi_initialize_string function in cgi-bin/var.c in the web interface does not
  properly handle parameter values containing a % (percent) character without two subsequent hex
  characters, which allows context-dependent attackers to obtain sensitive information from cupsd
  process memory via a crafted request.

  - CVE-2010-0540: Cross-site request forgery (CSRF).");

  script_tag(name:"affected", value:"CUPS prior to version 1.4.4.");

  script_tag(name:"solution", value:"Updates to version 1.4.4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40889");
  script_xref(name:"URL", value:"http://cups.org/articles.php?L596");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3577");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3498");
  script_xref(name:"URL", value:"https://github.com/apple/cups/releases/tag/release-1.4.4");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+")
  exit( 0 ); # Version is not exact enough

path = infos["location"];

if( version_is_less( version:vers, test_version:"1.4.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.4", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
