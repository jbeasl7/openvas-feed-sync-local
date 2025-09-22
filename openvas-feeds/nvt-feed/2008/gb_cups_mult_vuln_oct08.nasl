# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800111");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-14 16:26:50 +0200 (Tue, 14 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.3.9 Multiple Vulnerabilities (Oct 2008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) service is prone to buffer
  overflow and integer Overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2008-3641: an error in the implementation of the HP-GL/2 filter and can be exploited to cause
  buffer overflows with HP-GL/2 files containing overly large pen numbers.

  - CVE-2008-3639: an error within the read_rle8() and read_rle16() functions when parsing malformed
  Run Length Encoded(RLE) data within Silicon Graphics Image(SGI) files and can exploited to cause
  heap-based buffer overflow with a specially crafted SGI file.

  - CVE-2008-3640: an error within the WriteProlog() function included in the texttops utility and can
  be exploited to cause a heap-based buffer overflow with specially crafted file.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code or compromise a vulnerable system.");

  script_tag(name:"affected", value:"CUPS prior to version 1.3.9.");

  script_tag(name:"solution", value:"Update to version 1.3.9 or later.");

  script_xref(name:"URL", value:"http://cups.org/articles.php?L575");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31681");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31688");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31690");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32226/");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2782/");
  script_xref(name:"URL", value:"https://github.com/apple/cups/releases/tag/release-1.3.9");

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

if( version_is_less( version:vers, test_version:"1.3.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.9" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
