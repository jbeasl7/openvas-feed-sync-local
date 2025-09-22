# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810632");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2016-7857", "CVE-2016-7858", "CVE-2016-7859", "CVE-2016-7860",
                "CVE-2016-7861", "CVE-2016-7862", "CVE-2016-7863", "CVE-2016-7864",
                "CVE-2016-7865");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 17:12:00 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-17 16:27:06 +0530 (Fri, 17 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB16-37) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Type confusion vulnerabilities.

  - Use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to take control of the affected system, and lead to
  code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 23.0.0.207 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 23.0.0.207 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-37.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94153");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/MacOSX/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"23.0.0.207"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"23.0.0.207");
  security_message(data:report);
  exit(0);
}
