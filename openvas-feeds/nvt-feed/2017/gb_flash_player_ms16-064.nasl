# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810654");
  script_version("2023-11-03T05:05:46+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-1096", "CVE-2016-1097", "CVE-2016-1098", "CVE-2016-1099",
                "CVE-2016-1100", "CVE-2016-1101", "CVE-2016-1102", "CVE-2016-1103",
                "CVE-2016-1104", "CVE-2016-1105", "CVE-2016-1106", "CVE-2016-1107",
                "CVE-2016-1108", "CVE-2016-1109", "CVE-2016-1110", "CVE-2016-4108",
                "CVE-2016-4109", "CVE-2016-4110", "CVE-2016-4111", "CVE-2016-4112",
                "CVE-2016-4113", "CVE-2016-4114", "CVE-2016-4115", "CVE-2016-4116",
                "CVE-2016-4117", "CVE-2016-4120", "CVE-2016-4121", "CVE-2016-4160",
                "CVE-2016-4161", "CVE-2016-4162", "CVE-2016-4163");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 17:28:00 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"creation_date", value:"2017-03-18 14:50:56 +0530 (Sat, 18 Mar 2017)");
  script_name("Microsoft IE And Microsoft Edge Flash Player Multiple Vulnerabilities (3157993)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-064.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple type confusion vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - A heap buffer overflow vulnerability.

  - A buffer overflow vulnerability.

  - Multiple memory corruption vulnerabilities.

  - A vulnerability in the directory search path used to find resources.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code and
  also some unknown impact.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-064");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90620");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90505");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90619");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90617");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90616");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-15.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_flash_player_within_ie_edge_detect.nasl");
  script_mandatory_keys("AdobeFlash/IE_or_EDGE/Installed");

  exit(0);
}

include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1, win2012R2:1, win10:1,
                   win10x64:1) <= 0)
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

if(version_is_less(version:vers, test_version:"21.0.0.242")) {
  report = report_fixed_ver(file_checked:path, file_version:vers, vulnerable_range:"Less than 21.0.0.242");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
