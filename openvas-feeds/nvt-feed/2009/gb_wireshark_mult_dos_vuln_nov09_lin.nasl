# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801033");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3549", "CVE-2009-3551");
  script_name("Wireshark Multiple Denial Of Service Vulnerability (Nov 2009) - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37175");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36846");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3061");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3689");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.3.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-07.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");
  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.2 on Linux.");
  script_tag(name:"insight", value:"- An alignment error within the 'dissect_paltalk()' function in
    epan/dissectors/packet-paltalk.c of the Paltalk dissector can be
    exploited to cause a crash.

  - An off-by-one error within the 'dissect_negprot_response()' function in
    epan/dissectors/packet-smb.c of the SMB dissector can be exploited to
    cause a crash.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple Denial of Service vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.3.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.2")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range: "1.2.0 - 1.2.2", install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
