# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818553");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747", "CVE-2017-7529",
                "CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845", "CVE-2019-20372");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:13:00 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"creation_date", value:"2021-09-22 17:41:46 +0530 (Wed, 22 Sep 2021)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Multiple Vulnerabilities (HT212818)");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Apple.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors in
  nginx.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service, bypass authentication and leak potentially
  sensitive information.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 13");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 13 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212818");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || version_is_less(version:osVer, test_version:"11.3")){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

xcVer = infos["version"];
xcpath = infos["location"];

if(version_is_less(version:xcVer, test_version:"13"))
{
  report = report_fixed_ver(installed_version:xcVer, fixed_version:"13", install_path:xcpath);
  security_message(data:report);
  exit(0);
}
exit(0);
