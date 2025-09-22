# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:photoshop_cc2017";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812210");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2017-11304", "CVE-2017-11303");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-14 16:32:00 +0000 (Thu, 14 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-11-16 16:38:07 +0530 (Thu, 16 Nov 2017)");
  script_name("Adobe Photoshop CC Multiple Remote Code Execution Vulnerabilities (APSB17-34) - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to multiple remote code execution
  (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to a memory
  corruption error and an use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected application and gain elevated privileges.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2017 18.1.1 (2017.1.1)
  and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2017
  18.1.2 (2017.1.2) or Photoshop CC 2018 19.0 (2018.0) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb17-34.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101829");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"18.1.1")) {
  report = report_fixed_ver(installed_version:"CC 2017 " + vers, fixed_version:"CC 2017 18.1.2 or CC 2018 19.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
