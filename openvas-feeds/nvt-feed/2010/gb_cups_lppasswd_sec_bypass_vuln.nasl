# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800488");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2010-0393");

  script_name("CUPS < 1.4.3 Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"Common UNIX Printing System (CUPS) is prone to a security
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error within the '_cupsGetlang()' function, as
  used by 'lppasswd.c' in 'lppasswd', relies on an environment variable to determine the file that
  provides localized message strings.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to gain privileges
  via a file that contains crafted localization data with format string specifiers.");

  script_tag(name:"affected", value:"CUPS prior to version 1.4.3.");

  script_tag(name:"solution", value:"Update to version 1.4.3 or later.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-906-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38524");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=558460");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3482");
  script_xref(name:"URL", value:"https://github.com/apple/cups/releases/tag/release-1.4.3");

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

if( version_is_less( version:vers, test_version:"1.4.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
