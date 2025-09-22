# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815826");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-8784", "CVE-2019-8783", "CVE-2019-8811", "CVE-2019-8814",
                "CVE-2019-8816", "CVE-2019-8819", "CVE-2019-8820", "CVE-2019-8821",
                "CVE-2019-8822", "CVE-2019-8823", "CVE-2019-8815");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 13:16:00 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2019-11-05 15:24:05 +0530 (Tue, 05 Nov 2019)");
  script_name("Apple iCloud Security Updates (HT210728)");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple memory
  corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code with system privileges.");

  script_tag(name:"affected", value:"Apple iCloud version below 7.15 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 7.15 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210728");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

#iCloud for Windows 7.x works with versions of Microsoft Windows 7, 8, 8.1, and early versions of Windows 10
#Ignore for May 2019 Update version of Microsoft Windows 10 and later
if(version_is_less(version:vers, test_version:"7.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.15", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
