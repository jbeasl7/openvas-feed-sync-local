# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832959");
  script_version("2024-05-03T05:05:25+0000");
  script_cve_id("CVE-2023-44341", "CVE-2023-44342", "CVE-2023-44343", "CVE-2023-44344",
                "CVE-2023-44345", "CVE-2023-44346", "CVE-2023-44347");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-03 05:05:25 +0000 (Fri, 03 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-29 01:41:14 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-04-24 06:43:04 +0530 (Wed, 24 Apr 2024)");
  script_name("Adobe InDesign Multiple Vulnerabilities (APSB23-55) - Mac OS X");

  script_tag(name:"summary", value:"Adobe InDesign is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2023-44341: Application denial-of-service vulnerability

  - CVE-2023-44342: Memory leak vulnerability

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause a memory leak and denial of service.");

  script_tag(name:"affected", value:"Adobe InDesign 18.x through 18.5 and 17.x
  through 17.4.2 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 18.5.1 or 19.0 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb23-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_indesign_server_detect_macosx.nasl");
  script_mandatory_keys("InDesign/Server/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "18.0", test_version2: "18.5")) {
  fix = "18.5.1";
}

if(version_in_range(version: vers, test_version: "17.0", test_version2: "17.4.2")) {
  fix = "19.0";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
