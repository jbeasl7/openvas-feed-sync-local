# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810576");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-4692", "CVE-2016-7635", "CVE-2016-7652", "CVE-2016-7656",
                "CVE-2016-4743", "CVE-2016-7586", "CVE-2016-7587", "CVE-2016-7610",
                "CVE-2016-7611", "CVE-2016-7639", "CVE-2016-7640", "CVE-2016-7641",
                "CVE-2016-7642", "CVE-2016-7645", "CVE-2016-7646", "CVE-2016-7648",
                "CVE-2016-7649", "CVE-2016-7654", "CVE-2016-7589", "CVE-2016-7592",
                "CVE-2016-7598", "CVE-2016-7599", "CVE-2016-7632", "CVE-2016-7614");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-27 01:29:00 +0000 (Thu, 27 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-28 10:49:30 +0530 (Tue, 28 Feb 2017)");
  script_name("Apple iCloud Multiple Vulnerabilities (Feb 2017) - Windows");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple memory corruption errors in WebKit.

  - A validation error in WebKit.

  - An error in handling of JavaScript prompts.

  - An error in the handling of HTTP redirects.

  - The iCloud desktop client failed to clear sensitive information in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, cause unexpected application termination
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple iCloud versions before 6.1
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 6.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95733");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!icVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:icVer, test_version:"6.1"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"6.1");
  security_message(data:report);
  exit(0);
}
