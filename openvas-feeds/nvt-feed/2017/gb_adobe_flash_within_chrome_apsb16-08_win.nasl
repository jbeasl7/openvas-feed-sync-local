# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810663");
  script_version("2024-02-12T05:05:32+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963",
                "CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989",
                "CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0992", "CVE-2016-0993",
                "CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-0997",
                "CVE-2016-0998", "CVE-2016-0999", "CVE-2016-1000", "CVE-2016-1001",
                "CVE-2016-1002", "CVE-2016-1005", "CVE-2016-1010");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 19:19:00 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"creation_date", value:"2017-03-18 15:49:21 +0530 (Sat, 18 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB16-08) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple integer overflow vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - A heap overflow vulnerability.

  - Multiple memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 21.0.0.182 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 21.0.0.182 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96496");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95212");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84311");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84312");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96850");

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

if(version_is_less(version:playerVer, test_version:"21.0.0.182"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"21.0.0.182");
  security_message(data:report);
  exit(0);
}
