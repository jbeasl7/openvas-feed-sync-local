# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815478");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2019-16319");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-11 14:16:00 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"creation_date", value:"2019-10-07 10:56:20 +0530 (Mon, 07 Oct 2019)");
  script_name("Wireshark Security Updates (wnpa-sec-2019-21) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to missing message length
  checking in plugins/epan/gryphon/packet-gryphon.c.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to make wireshark consume excessive CPU resources by injecting a malformed
  packet onto the wire or by convincing someone to read a malformed packet trace
  file.");

  script_tag(name:"affected", value:"Wireshark versions 3.0.0 to 3.0.3 and
  2.6.0 to 2.6.10.");

  script_tag(name:"solution", value:"Update to version 3.0.4, 2.6.11 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-21");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
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

if(version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.3")) {
  fix = "3.0.4";
}

else if(version_in_range(version:vers, test_version:"2.6.0", test_version2:"2.6.10")) {
  fix = "2.6.11";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
