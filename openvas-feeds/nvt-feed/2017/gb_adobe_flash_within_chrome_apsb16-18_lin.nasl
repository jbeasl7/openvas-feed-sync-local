# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810653");
  script_version("2024-02-12T05:05:32+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-4122", "CVE-2016-4123", "CVE-2016-4124", "CVE-2016-4125",
                "CVE-2016-4127", "CVE-2016-4128", "CVE-2016-4129", "CVE-2016-4130",
                "CVE-2016-4131", "CVE-2016-4132", "CVE-2016-4133", "CVE-2016-4134",
                "CVE-2016-4135", "CVE-2016-4136", "CVE-2016-4137", "CVE-2016-4138",
                "CVE-2016-4139", "CVE-2016-4140", "CVE-2016-4141", "CVE-2016-4142",
                "CVE-2016-4143", "CVE-2016-4144", "CVE-2016-4145", "CVE-2016-4146",
                "CVE-2016-4147", "CVE-2016-4148", "CVE-2016-4149", "CVE-2016-4150",
                "CVE-2016-4151", "CVE-2016-4152", "CVE-2016-4153", "CVE-2016-4154",
                "CVE-2016-4155", "CVE-2016-4156", "CVE-2016-4166", "CVE-2016-4171");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-24 16:33:00 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2017-03-17 20:48:55 +0530 (Fri, 17 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB16-18) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple type confusion vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - Multiple heap buffer overflow vulnerabilities.

  - Multiple memory corruption vulnerabilities.

  - A vulnerability in the directory search path used to find resources.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the same-origin-policy and lead to information disclosure,
  and code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 22.0.0.192 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 22.0.0.192 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-18.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91256");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91255");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91253");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91250");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91249");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91184");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/Lin/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"22.0.0.192"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"22.0.0.192");
  security_message(data:report);
  exit(0);
}
