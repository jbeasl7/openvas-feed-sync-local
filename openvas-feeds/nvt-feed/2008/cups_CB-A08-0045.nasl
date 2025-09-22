# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90017");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2008-1722", "CVE-2008-0047");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.3.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) service is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2008-0047: Heap-based buffer overflow in the cgiCompileSearch function, when printer sharing
  is enabled, allows remote attackers to execute arbitrary code via crafted search expressions.

  - CVE-2008-1722: Multiple integer overflows in (1) filter/image-png.c and (2) filter/image-zoom.c
  allow attackers to cause a denial of service (crash) and trigger memory corruption, as demonstrated
  via a crafted PNG image.");

  script_tag(name:"affected", value:"CUPS prior to version 1.3.8.");

  script_tag(name:"solution", value:"Update to version 1.3.8 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28781");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.3.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.8" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
