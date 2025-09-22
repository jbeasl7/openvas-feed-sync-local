# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810509");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2017-3316", "CVE-2017-3332", "CVE-2017-3290", "CVE-2016-5545");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-04 17:55:00 +0000 (Mon, 04 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-01-19 10:28:03 +0530 (Thu, 19 Jan 2017)");
  script_name("Oracle VirtualBox Multiple Unspecified Vulnerabilities - 01 (Jan 2017) - Windows");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws rae due to multiple
  unspecified errors in sub components 'GUI', 'VirtualBox SVGA Emulation'
  and 'Shared Folder'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 5.0.32
  and prior to 5.1.14 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.0.32 or 5.1.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95601");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95590");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.0") {
  if(version_is_less(version:vers, test_version:"5.0.32")) {
    fix = "5.0.32";
    VULN = TRUE;
  }
}

else if(vers =~ "^5\.1") {
  if(version_is_less(version:vers, test_version:"5.1.14")) {
    fix = "5.1.14";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
