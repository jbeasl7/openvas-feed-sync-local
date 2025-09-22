# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815225");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2019-8342");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-06-28 13:10:03 +0530 (Fri, 28 Jun 2019)");
  script_name("Foxit Reader Privilege Escalation Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an incorrect permission
  set in libqcocoa.dylib.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to elevate privileges on a vulnerable system.");

  script_tag(name:"affected", value:"Foxit Reader version 3.1.0.0111 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader 3.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_foxit_reader_detect_macosx.nasl");
  script_mandatory_keys("foxit/reader/mac_osx/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos["version"];
pdfPath = infos["location"];

if(version_is_equal(version:pdfVer, test_version:"3.1.0.0111"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"3.2", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
