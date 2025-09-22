# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811842");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-5121", "CVE-2017-5122");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-09 02:29:00 +0000 (Sat, 09 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-09-25 12:15:01 +0530 (Mon, 25 Sep 2017)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_21-2017-09) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple out-of-bounds access errors in V8.

  - Various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to access information and can
  also  cause a crash.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 61.0.3163.100 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  61.0.3163.100 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop_21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100947");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"61.0.3163.100"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"61.0.3163.100");
  security_message(data:report);
  exit(0);
}

exit(99);
