# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811003");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2017-7704");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-19 15:33:39 +0530 (Wed, 19 Apr 2017)");
  script_name("Wireshark 'DOF dissector' DoS Vulnerability - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the 'DOF dissector'
  could go into an infinite loop, triggered by packet injection or a malformed
  capture file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop which may cause
  denial-of-service condition.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 through 2.2.5
  on Windows.");

  script_tag(name:"solution", value:"Update to version 2.2.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-17.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97634");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^2\.2") {
  if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.5")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.2.6", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
