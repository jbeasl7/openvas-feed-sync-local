# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814603");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-4440", "CVE-2018-4439", "CVE-2018-4437", "CVE-2018-4464",
                "CVE-2018-4441", "CVE-2018-4442", "CVE-2018-4443", "CVE-2018-4438");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 16:05:00 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-12-06 11:23:39 +0530 (Thu, 06 Dec 2018)");
  script_name("Apple iCloud Security Updates (HT209346) - Windows");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A logic issue was addressed with improved state management.

  - A logic issue was addressed with improved validation.

  - Multiple memory corruption issues were addressed with improved memory handling.

  - A logic issue existed resulting in memory corruption.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  conduct spoofing attacks and run arbitrary code execution.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.9 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 7.9 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209346");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
icVer = infos["version"];
icPath = infos["location"];

if(version_is_less(version:icVer, test_version:"7.9"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"7.9", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(99);
