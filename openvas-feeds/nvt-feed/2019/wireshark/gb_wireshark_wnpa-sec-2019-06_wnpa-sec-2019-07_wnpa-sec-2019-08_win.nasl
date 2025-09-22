# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814866");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 18:29:00 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-28 11:32:38 +0530 (Thu, 28 Feb 2019)");
  script_name("Wireshark Security Updates (wnpa-sec-2019-06, wnpa-sec-2019-07, wnpa-sec-2019-08) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - NULL pointer dereferences in epan/dissectors/asn1/tcap/tcap.cnf
    and pan/dissectors/packet-rpcap.c

  - Buffer overflow error in epan/dissectors/packet-ber.c");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash Wireshark dissectors by injecting a malformed packet into the network
  or by tricking a victim into opening a malicious packet trace file.");

  script_tag(name:"affected", value:"Wireshark versions 2.4.0 to 2.4.12 and
  2.6.0 to 2.6.6.");

  script_tag(name:"solution", value:"Update to version 2.4.13, 2.6.7 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-06.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-07.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-08.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.12")) {
  fix = "2.4.13";
}

else if(version_in_range(version:vers, test_version:"2.6.0", test_version2:"2.6.6")) {
  fix = "2.6.7";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
