# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821250");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2022-24765", "CVE-2022-26747");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 20:14:00 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-19 11:15:30 +0530 (Thu, 19 May 2022)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Security Update (HT213261)");

  script_tag(name:"summary", value:"Apple Xcode is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A logic issue due to improper state management.

  - An improper check.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 13.4 on
  macOS Monterey 12 and later.");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 13.4 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213261");
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

if(version_is_less(version:xcVer, test_version:"13.4"))
{
  report = report_fixed_ver(installed_version:xcVer, fixed_version:"13.4", install_path:xcpath);
  security_message(data:report);
  exit(0);
}
exit(0);
