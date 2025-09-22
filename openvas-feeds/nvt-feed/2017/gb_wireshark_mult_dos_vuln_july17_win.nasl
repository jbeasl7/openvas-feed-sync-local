# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811426");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2017-11408", "CVE-2017-11407", "CVE-2017-11406", "CVE-2017-11410",
                "CVE-2017-11411");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-20 18:02:24 +0530 (Thu, 20 Jul 2017)");
  script_name("Wireshark Multiple DoS Vulnerabilities (Jul 2017) - Windows");

  script_tag(name:"summary", value:"wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  an error in 'DOCSIS', 'MQ', 'AMQP', 'openSAFETY', 'WBXML' dissectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to crash the affected application, resulting in denial-of-service
  conditions.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 to 2.2.7, and 2.0.0
  to 2.0.13 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.8 or
  2.0.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-34.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99894");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-35.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-36.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-13.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-28.html");

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

version = infos["version"];
location = infos["location"];

if(version =~ "^2\.0") {
  if(version_is_less(version:version, test_version:"2.0.14")) {
    fix = "2.0.14";
  }
}

else if(version =~ "^2\.2") {
  if(version_is_less(version:version, test_version:"2.2.8")) {
    fix = "2.2.8";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
