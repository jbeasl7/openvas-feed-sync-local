# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800142");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:35:00 +0000 (Thu, 28 Dec 2023)");

  script_cve_id("CVE-2008-5183", "CVE-2008-5184");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.3.8 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) Service is prone to a denial
  of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in web interface (cgi-bin/admin.c), which
  uses the guest username when a user is not logged on to the web server. This leads to CSRF attacks
  with the add/cancel RSS subscription functions.");

  script_tag(name:"impact", value:"Successful exploitation causes Denial of Service condition.");

  script_tag(name:"affected", value:"CUPS versions prior to 1.3.8 on Linux.");

  script_tag(name:"solution", value:"Update to version 1.3.8 or later.");

  script_xref(name:"URL", value:"http://www.cups.org/str.php?L2774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32419");
  script_xref(name:"URL", value:"http://www.gnucitizen.org/blog/pwning-ubuntu-via-cups/");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/11/19/3");

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

if( version_is_less( version:vers, test_version:"1.3.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.8" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
