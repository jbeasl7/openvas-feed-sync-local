# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100685");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-06-21 20:36:15 +0200 (Mon, 21 Jun 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2010-0542", "CVE-2010-2431", "CVE-2010-2432");

  script_name("CUPS < 1.4.4 Multiple DoS and Privilege Escalation Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("Privilege escalation");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) service is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2010-0542: The _WriteProlog function in texttops.c in texttops in the Text Filter subsystem
  does not check the return values of certain calloc calls.

  - CVE-2010-2431: The cupsFileOpen function allows local users, with lp group membership, to
  overwrite arbitrary files via a symlink attack.

  - CVE-2010-2432: The cupsDoAuthentication function in auth.c in the client, when HAVE_GSSAPI is
  omitted, does not properly handle a demand for authorization, which allows remote CUPS servers to
  cause a denial of service (infinite loop) via HTTP_UNAUTHORIZED responses.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code
  with the privileges of a user running the application. Failed exploit attempts likely cause
   denial of service conditions.");

  script_tag(name:"affected", value:"CUPS versions prior to 1.4.4.");

  script_tag(name:"solution", value:"Update to version 1.4.4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40943");
  script_xref(name:"URL", value:"http://cups.org/articles.php?L596");
  script_xref(name:"URL", value:"http://cups.org/str.php?L3516");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3516");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3510");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3518");
  script_xref(name:"URL", value:"https://github.com/apple/cups/releases/tag/release-1.4.4");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+")
  exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.4.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
