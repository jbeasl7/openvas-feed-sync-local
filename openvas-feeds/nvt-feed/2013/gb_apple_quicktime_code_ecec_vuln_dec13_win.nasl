# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804053");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2010-1819");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-12-31 12:44:42 +0530 (Tue, 31 Dec 2013)");
  script_name("Apple QuickTime Pictureviewer Arbitrary Code Execution Vulnerability (Dec 2013) - Windows");

  script_tag(name:"summary", value:"Apple QuickTime is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.6.8 or later.");

  script_tag(name:"insight", value:"Flaw is due to the PictureViewer application loading libraries
  (e.g. CoreGraphics.dll) in an insecure manner.");

  script_tag(name:"affected", value:"Apple QuickTime version before 7.6.8 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code and
  compromise a vulnerable system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4339");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42774");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41123");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010/Sep/msg00003.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"7.68.75.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.68.75.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
