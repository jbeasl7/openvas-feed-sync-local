# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811597");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2017-13765", "CVE-2017-13767");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-09-05 15:42:03 +0530 (Tue, 05 Sep 2017)");
  script_name("Wireshark 'IrCOMM' And 'MSDP' Dissectors DoS Vulnerabilities - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Missing length validation in 'epan/dissectors/packet-msdp.c' so that the
    MSDP dissector could go into an infinite loop.

  - Missing length validation in 'plugins/irda/packet-ircomm.c' so that the
    IrCOMM dissector could read past the end of a buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to make Wireshark crash and also consume excessive CPU resources by
  injecting a malformed packet onto the wire or by convincing someone to read a
  malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0, 2.2.0 to 2.2.8,
  2.0.0 to 2.0.14 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.1 or
  2.2.9 or 2.0.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-41.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100551");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100549");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-38.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version =~ "^2\.0") {
  if(version_is_less(version:version, test_version:"2.0.15")) {
    fix = "2.0.15";
  }
}

else if(version =~ "^2\.2") {
  if(version_is_less(version:version, test_version:"2.2.9")) {
    fix = "2.2.9";
  }
}

else if(version == "2.4.0") {
  fix = "2.4.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
