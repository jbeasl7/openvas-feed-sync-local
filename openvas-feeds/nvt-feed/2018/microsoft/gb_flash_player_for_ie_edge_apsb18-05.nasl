# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813030");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2018-4920", "CVE-2018-4919");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 16:25:00 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"creation_date", value:"2018-03-14 11:17:28 +0530 (Wed, 14 Mar 2018)");
  script_name("Microsoft IE And Microsoft Edge Flash Player Multiple RCE Vulnerabilities (APSB18-05)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_flash_player_within_ie_edge_detect.nasl");
  script_mandatory_keys("AdobeFlash/IE_or_EDGE/Installed");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-05.html");

  script_tag(name:"summary", value:"Adobe Flash Player within Microsoft Edge or Internet Explorer is
  prone to multiple remote code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to a type confusion
  error and use-after-free error in the flash player.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow an attacker to execute arbitrary code on affected system and take
  control of the affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player within Microsoft Edge or
  Internet Explorer on:

  - Windows 10 Version 1511 for x32/x64

  - Windows 10 Version 1607 for x32/x64

  - Windows 10 Version 1703 for x32/x64

  - Windows 10 Version 1709 for x32/x64

  - Windows 10 x32/x64

  - Windows 8.1 for x32/x64

  - Windows Server 2012/2012 R2/2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

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
  path += "\Flashplayerapp.exe";
} else {
  path = "Could not find the install location";
}

if(version_is_less(version:vers, test_version:"29.0.0.113")) {
  report = report_fixed_ver(file_checked:path, file_version:vers, vulnerable_range:"Less than 29.0.0.113");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
