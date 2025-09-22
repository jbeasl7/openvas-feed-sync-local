# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810540");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2016-2317");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-02-07 19:04:50 +0530 (Tue, 07 Feb 2017)");
  script_name("GraphicsMagick 'SVG File Parsing' Denial of Service Vulnerability - 02 - Windows");

  script_tag(name:"summary", value:"GraphicsMagick is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to heap and stack buffer
  overflow errors in TracePoint function in magick/render.c, GetToken function
  in magick/utility.c, and GetTransformTokens function in coders/svg.c related
  with the parsing and processing of SVG files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service via a crafted SVG file.");

  script_tag(name:"affected", value:"GraphicsMagick versions 1.3.23 and
  1.3.24 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 1.3.25 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/05/31/3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83241");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q1/297");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(gmVer =~ "^1\.3\.")
{
  if(version_in_range(version:gmVer, test_version:"1.3.23", test_version2:"1.3.24"))
  {
    report = report_fixed_ver(installed_version:gmVer, fixed_version:"1.3.25");
    security_message(data:report);
    exit(0);
  }
}

exit(0);
