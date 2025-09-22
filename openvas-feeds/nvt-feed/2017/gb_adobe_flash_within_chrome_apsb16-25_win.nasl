# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810647");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2016-4172", "CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175",
                "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179",
                "CVE-2016-4180", "CVE-2016-4181", "CVE-2016-4182", "CVE-2016-4183",
                "CVE-2016-4184", "CVE-2016-4185", "CVE-2016-4186", "CVE-2016-4187",
                "CVE-2016-4188", "CVE-2016-4189", "CVE-2016-4190", "CVE-2016-4217",
                "CVE-2016-4218", "CVE-2016-4219", "CVE-2016-4220", "CVE-2016-4221",
                "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225",
                "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229",
                "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4233",
                "CVE-2016-4234", "CVE-2016-4235", "CVE-2016-4236", "CVE-2016-4237",
                "CVE-2016-4238", "CVE-2016-4239", "CVE-2016-4240", "CVE-2016-4241",
                "CVE-2016-4242", "CVE-2016-4243", "CVE-2016-4244", "CVE-2016-4245",
                "CVE-2016-4246", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249",
                "CVE-2016-7020");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-20 02:50:00 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-03-17 20:19:13 +0530 (Fri, 17 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB16-25) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A race condition vulnerability.

  - Multiple type confusion vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - A heap buffer overflow vulnerability.

  - Multiple memory corruption vulnerabilities.

  - Multiple stack corruption vulnerabilities.

  - A security bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers lead to information disclosure and code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 22.0.0.209 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 22.0.0.209 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-25.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94192");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91719");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91723");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91720");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91721");
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

if(version_is_less(version:playerVer, test_version:"22.0.0.209"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"22.0.0.209");
  security_message(data:report);
  exit(0);
}
