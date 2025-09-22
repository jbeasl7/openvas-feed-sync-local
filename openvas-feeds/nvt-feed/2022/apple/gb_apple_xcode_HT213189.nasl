# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820031");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2019-14379", "CVE-2021-44228", "CVE-2022-22601", "CVE-2022-22602",
                "CVE-2022-22603", "CVE-2022-22604", "CVE-2022-22605", "CVE-2022-22606",
                "CVE-2022-22607", "CVE-2022-22608");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-03-17 11:44:49 +0530 (Thu, 17 Mar 2022)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Security Update (HT213189)");

  script_tag(name:"summary", value:"Apple Xcode is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple issues in iTMSTransporter.

  - An out-of-bounds read error related to an improper bounds checking.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution and also cause unexpected application
  termination.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 13.3 on
  macOS Monterey 12 and later.");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 13.3 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213189");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\."){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

xcVer = infos["version"];
xcpath = infos["location"];

if(version_is_less(version:xcVer, test_version:"13.3"))
{
  report = report_fixed_ver(installed_version:xcVer, fixed_version:"13.3", install_path:xcpath);
  security_message(data:report);
  exit(0);
}
exit(0);
