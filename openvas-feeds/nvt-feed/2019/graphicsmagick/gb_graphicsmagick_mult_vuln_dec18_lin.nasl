# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113331");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-02-07 13:20:22 +0200 (Thu, 07 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20184", "CVE-2018-20185", "CVE-2018-20189");

  script_name("GraphicsMagick < 1.3.32 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("os_detection.nasl", "gb_graphicsmagick_detect_lin.nasl");
  script_mandatory_keys("Host/runs_unixoide", "GraphicsMagick/Linux/Ver");

  script_tag(name:"summary", value:"GraphicsMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - There is a heap-based buffer overflow in the WriteTGAImage function of tga.c,
    which allows attackers to cause a denial of service via a crafted image file,
    because the number of rows or columns can exceed the pixel-dimension
    restrictions of the TGA specification.

  - There is a heap-based buffer over-read in the ReadBMP Image function of bmp.c,
    which allows attackers to cause a denial of service via a crafted bmp image file.
    This only affects GraphicsMagick installations on 32-bit platforms
    with customized BMP limits.

  - The ReadDIBImage of dib.c has a vulnerability allowing a crash and denial of service
    via a dib file that is crafted to appear with direct pixel values and also colomapping
    and therefore lacks indexes initialization.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause a denial of service.");
  script_tag(name:"affected", value:"GraphicsMagick prior to version 1.3.32.");
  script_tag(name:"solution", value:"Update to GraphicsMagick version 1.3.32 or later.");

  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106229");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/583");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/585");

  exit(0);
}

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.3.32" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.32", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
