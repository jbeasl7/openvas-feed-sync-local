# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815829");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2019-8800", "CVE-2019-8806");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-30 17:19:00 +0000 (Mon, 30 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-05 15:24:05 +0530 (Tue, 05 Nov 2019)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Arbitrary Code Execution Vulnerability (HT210729)");

  script_tag(name:"summary", value:"Apple Xcode is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption issue
  related to improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 11.2");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 11.2 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210729");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || version_is_less(version:osVer, test_version:"10.14.4")){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

xcVer = infos["version"];
xcpath = infos["location"];

if(version_is_less(version:xcVer, test_version:"11.2"))
{
  report = report_fixed_ver(installed_version:xcVer, fixed_version:"11.2", install_path:xcpath);
  security_message(data:report);
  exit(0);
}
exit(0);
