# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814088");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-12814", "CVE-2018-12813", "CVE-2018-12823", "CVE-2018-12816",
                "CVE-2018-12818", "CVE-2018-12819", "CVE-2018-12820", "CVE-2018-12821",
                "CVE-2018-12822");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-10-11 10:27:04 +0530 (Thu, 11 Oct 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Multiple Vulnerabilities (APSB18-27) - Windows");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple out-of-bounds read errors.

  - Multiple heap overflow errors.

  - An use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain conduct arbitrary code execution and information disclosure.");

  script_tag(name:"affected", value:"Adobe Digital Edition versions prior to 4.5.9 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.9 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb18-27.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
digitalVer = infos["version"];
digitalPath = infos["location"];

if(version_is_less(version:digitalVer, test_version:"4.5.9"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.9", install_path:digitalPath);
  security_message(data:report);
  exit(0);
}
exit(99);
