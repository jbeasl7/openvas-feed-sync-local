# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900349");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2009-0164");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.3.10 Improper Input Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to an improper input validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is cause due to insufficient validation of the HTTP Host
  header in a client request.");

  script_tag(name:"impact", value:"An attacker can use this weakness to carry out certain attacks such
  as DNS rebinding against the vulnerable server.");

  script_tag(name:"affected", value:"CUPS version prior to 1.3.10.");

  script_tag(name:"solution", value:"Upgrade to version 1.3.10 or later.");

  script_xref(name:"URL", value:"http://www.cups.org/str.php?L3118");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34665");
  script_xref(name:"URL", value:"http://www.cups.org/articles.php?L582");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=263070");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490597");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.3.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
