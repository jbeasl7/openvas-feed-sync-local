# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107608");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-03-09 18:20:49 +0100 (Sat, 09 Mar 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-19 02:15:00 +0000 (Wed, 19 Aug 2020)");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10177", "CVE-2018-10804", "CVE-2018-10805");

  script_name("ImageMagick 7.0.7.28 Multiple Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  script_tag(name:"summary", value:"ImageMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"In ImageMagick 7.0.7.28, there is an infinite loop in the ReadOneMNGImage function
  of the coders/png.c file. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted mng file.
  In addition to that a memory leaks exist in 'WriteTIFFImage in coders/tiff.c' and 'ReadYCBCRImage in coders/ycbcr.c'.");
  script_tag(name:"affected", value:"ImageMagick version 7.0.7.28.");
  script_tag(name:"solution", value:"Upgrade to ImageMagick version 7.0.7.31 or later.");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104591");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1054");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1095");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version: vers, test_version: "7.0.7.31")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "7.0.7.31", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
