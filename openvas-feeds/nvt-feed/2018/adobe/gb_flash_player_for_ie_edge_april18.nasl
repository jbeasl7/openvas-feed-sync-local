# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813210");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2018-4932", "CVE-2018-4933", "CVE-2018-4934", "CVE-2018-4935",
                "CVE-2018-4936", "CVE-2018-4937");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 17:17:00 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"creation_date", value:"2018-04-11 15:57:09 +0530 (Wed, 11 Apr 2018)");
  script_name("Microsoft IE And Microsoft Edge Flash Player Security Update (KB4093110)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4093110.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- A remote code execution (RCE) vulnerability that occurs due to a use-after-free
  condition.

  - Multiple RCE vulnerabilities that occur due to an
  out-of-bounds write error.

  - Multiple information disclosure vulnerabilities that occur due to an
  out-of-bounds read error.

  - An information disclosure vulnerability that occurs due to a heap overflow
  condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to gain th control of the affected system. Depending on the
  privileges associated with this application, an attacker could then install
  programs, view, change, or delete data, or create new accounts with full
  user rights.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1511

  - Microsoft Windows 10 Version 1607

  - Microsoft Windows 10 Version 1703

  - Microsoft Windows 10 Version 1709

  - Microsoft Windows 8.1

  - Microsoft Windows Server 2012/2012 R2/2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/4093110");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-08.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_flash_player_within_ie_edge_detect.nasl");
  script_mandatory_keys("AdobeFlash/IE_or_EDGE/Installed");

  exit(0);
}

include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1, win2012R2:1, win10:1,
                   win10x64:1, win2016:1) <= 0)
  exit(0);

cpe_list = make_list("cpe:/a:adobe:flash_player_internet_explorer", "cpe:/a:adobe:flash_player_edge");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
if(path) {
  path = path + "\Flashplayerapp.exe";
} else {
  path = "Could not find the install location";
}

if(version_is_less(version:vers, test_version:"29.0.0.140")) {
  report = report_fixed_ver(file_checked:path, file_version:vers, vulnerable_range:"Less than 29.0.0.140");
  security_message(data:report);
  exit(0);
}

exit(99);
