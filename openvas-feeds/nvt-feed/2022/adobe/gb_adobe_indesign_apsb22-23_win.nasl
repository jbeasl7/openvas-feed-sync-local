# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821115");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-28831", "CVE-2022-28832", "CVE-2022-28833");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-11 14:26:00 +0000 (Mon, 11 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-05-12 17:38:45 +0530 (Thu, 12 May 2022)");
  script_name("Adobe InDesign RCE Vulnerabilities (APSB22-23) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe May update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaws exist due to an out-of-bounds read error and out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Adobe InDesign 17.1 and earlier versions, 16.4.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update Adobe InDesign to version 17.2 or
  later, 16.4.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb22-23.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_in_range(version: vers, test_version: "17.0", test_version2: "17.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "17.2", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: vers, test_version: "16.0.0", test_version2: "16.4.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "16.4.2", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
