# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810627");
  script_version("2024-02-12T05:05:32+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-7867", "CVE-2016-7868", "CVE-2016-7869", "CVE-2016-7870",
                "CVE-2016-7871", "CVE-2016-7872", "CVE-2016-7873", "CVE-2016-7874",
                "CVE-2016-7875", "CVE-2016-7876", "CVE-2016-7877", "CVE-2016-7878",
                "CVE-2016-7879", "CVE-2016-7880", "CVE-2016-7881", "CVE-2016-7890",
                "CVE-2016-7892");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-16 22:01:00 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-03-17 15:43:50 +0530 (Fri, 17 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB16-39) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free vulnerabilities.

  - Buffer overflow vulnerabilities.

  - Memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to take control of the affected system, and lead to
  code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 24.0.0.186 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 24.0.0.186 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-39.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94877");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94871");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94873");
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

if(version_is_less(version:playerVer, test_version:"24.0.0.186"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"24.0.0.186");
  security_message(data:report);
  exit(0);
}
