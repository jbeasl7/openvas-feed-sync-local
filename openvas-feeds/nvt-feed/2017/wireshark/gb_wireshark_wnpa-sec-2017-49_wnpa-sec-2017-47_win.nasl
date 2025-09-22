# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812259");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2017-17083", "CVE-2017-17084", "CVE-2017-17085");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)");
  script_tag(name:"creation_date", value:"2017-12-15 11:37:23 +0530 (Fri, 15 Dec 2017)");
  script_name("Wireshark Security Updates (wnpa-sec-2017-49_wnpa-sec-2017-47) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors
  in 'NetBIOS', 'IWARP_MPA' and 'CIP Safety' dissectors, which fails to properly
  handle certain types of packets.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0 to 2.4.2, 2.2.0
  to 2.2.10 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.4.3 or
  2.2.11 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-47.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102071");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-48.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-49.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^2\.[24]\.") {
  if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.2")) {
    fix = "2.4.3";
  }

  else if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.10")) {
    fix = "2.2.11";
  }

  if(fix) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
