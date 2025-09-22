# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814149");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-4374", "CVE-2018-4377", "CVE-2018-4372", "CVE-2018-4373",
                "CVE-2018-4375", "CVE-2018-4376", "CVE-2018-4382", "CVE-2018-4386",
                "CVE-2018-4392", "CVE-2018-4416", "CVE-2018-4409", "CVE-2018-4378");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 20:25:00 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-10-31 10:29:04 +0530 (Wed, 31 Oct 2018)");
  script_name("Apple iCloud Security Updates (HT209198) - Windows");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An issue exiss in the method for determining prime numbers.

  - A cross-site scripting issue exists in Safari.

  - Multiple memory corruption, resource exhaustion, issues in memory
    handling.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code, bypass security restrictions and conduct
  cross-site scripting.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.8 on Windows");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 7.7 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209198");
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

if(version_is_less(version:icVer, test_version:"7.8"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"7.8", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(99);
