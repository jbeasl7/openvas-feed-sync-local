# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811948");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2017-15191");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 18:12:00 +0000 (Fri, 01 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-10-12 13:42:58 +0530 (Thu, 12 Oct 2017)");
  script_name("Wireshark Security Updates (wnpa-sec-2017-44) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the DMP dissector
  which could crash on processing malformed packet.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to make Wireshark crash by injecting
  a malformed packet onto the wire or by convincing someone to read a malformed
  packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0 to 2.4.1, 2.2.0
  to 2.2.9, 2.0.0 to 2.0.15 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.2, 2.2.10,
  2.0.16.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-44");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101227");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^2\.[024]") {

  if(version_in_range(version:version, test_version:"2.4.0", test_version2:"2.4.1")) {
    fix = "2.4.2";
  }

  else if(version_in_range(version:version, test_version:"2.2.0", test_version2:"2.2.9")) {
    fix = "2.2.10";
  }

  else if(version_in_range(version:version, test_version:"2.0.0", test_version2:"2.0.15")) {
    fix = "2.0.16";
  }

  if(fix) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
