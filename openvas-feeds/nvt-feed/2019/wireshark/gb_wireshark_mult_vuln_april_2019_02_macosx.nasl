# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814877");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2019-10900", "CVE-2019-10902", "CVE-2019-10898", "CVE-2019-10897");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-04-12 18:31:41 +0530 (Fri, 12 Apr 2019)");
  script_name("Wireshark 3.0.1 Security Updates (Apr 2019) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in TSDNS, Rbm, GSUP and IEEE 802.11 dissector");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to crash Wireshark dissectors and make Wireshark
  consume excessive CPU resources by injecting a malformed packet onto the wire
  or by convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 3.0.0.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-13");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-16");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-12");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-11");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"3.0.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
