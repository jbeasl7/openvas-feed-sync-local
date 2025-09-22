# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811946");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2017-15193", "CVE-2017-15192");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-17 20:01:00 +0000 (Tue, 17 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-10-12 13:42:13 +0530 (Thu, 12 Oct 2017)");
  script_name("Wireshark Security Updates (wnpa-sec-2017-43_wnpa-sec-2017-42) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The MBIM dissector could crash or exhaust system memory.

  - Attribute Protocol dissector could crash.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to make Wireshark crash or exhaust
  system memory by injecting a malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file. It may be possible to make
  Wireshark crash by injecting a malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0 to 2.4.1, 2.2.0 to 2.2.9 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.2, 2.2.10
  or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-43");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101235");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-42");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
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

if(version =~ "^2\.[24]") {

  if(version_in_range(version:version, test_version:"2.4.0", test_version2:"2.4.1")) {
    fix = "2.4.2";
  }

  else if(version_in_range(version:version, test_version:"2.2.0", test_version2:"2.2.9")) {
    fix = "2.2.10";
  }

  if(fix) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
