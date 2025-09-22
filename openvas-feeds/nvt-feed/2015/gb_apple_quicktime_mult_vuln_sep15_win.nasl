# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805969");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-3788", "CVE-2015-3789", "CVE-2015-3790", "CVE-2015-3791",
                "CVE-2015-3792", "CVE-2015-5751", "CVE-2015-5779", "CVE-2015-5785",
                "CVE-2015-5786");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-09-01 17:24:20 +0530 (Tue, 01 Sep 2015)");
  script_name("Apple QuickTime Multiple Vulnerabilities (Sep 2015) - Windows");

  script_tag(name:"summary", value:"Apple QuickTime is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple memory
  corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have unexpected application termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Apple QuickTime version before 7.7.8 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.7.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Aug/msg00004.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76340");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76443");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76444");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.78.80.95")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.78.80.95", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
