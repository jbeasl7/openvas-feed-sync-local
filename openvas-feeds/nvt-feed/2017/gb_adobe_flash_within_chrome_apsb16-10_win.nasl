# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810667");
  script_version("2024-02-12T05:05:32+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-1006", "CVE-2016-1011", "CVE-2016-1012", "CVE-2016-1013",
                "CVE-2016-1014", "CVE-2016-1015", "CVE-2016-1016", "CVE-2016-1017",
                "CVE-2016-1018", "CVE-2016-1019", "CVE-2016-1020", "CVE-2016-1021",
                "CVE-2016-1022", "CVE-2016-1023", "CVE-2016-1024", "CVE-2016-1025",
                "CVE-2016-1026", "CVE-2016-1027", "CVE-2016-1028", "CVE-2016-1029",
                "CVE-2016-1030", "CVE-2016-1031", "CVE-2016-1032", "CVE-2016-1033");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-10 20:10:00 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-03-18 16:05:37 +0530 (Sat, 18 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB16-10) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple type confusion vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - Multiple memory corruption vulnerabilities.

  - A stack overflow vulnerability.

  - A vulnerability in the directory search path used to find resources.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow remote attackers to bypass memory layout randomization mitigations,
  also leads to code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 21.0.0.213 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 21.0.0.213 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-10.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96525");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96593");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96181");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95376");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85933");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90952");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96014");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95935");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"21.0.0.213"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"21.0.0.213");
  security_message(data:report);
  exit(0);
}
