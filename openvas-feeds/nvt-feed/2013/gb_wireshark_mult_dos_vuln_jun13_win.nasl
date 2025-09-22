# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803652");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2013-4081", "CVE-2013-4074");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-05-28 13:30:52 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark Multiple DoS Vulnerabilities (Jun 2013) - Windows");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028648");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60505");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of
  service via a crafted packet.");
  script_tag(name:"affected", value:"Wireshark 1.6.x before 1.6.16, 1.8.x before 1.8.8 on Windows");
  script_tag(name:"insight", value:"- 'http_payload_subdissector' function in epan/dissectors/packet-http.c in
     HTTP dissector does not determine when to use a recursive approach.

  - 'dissect_capwap_data' function in epan/dissectors/packet-capwap.c in CAPWAP
    dissector incorrectly uses a -1 data value to represent an error condition.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.16 or 1.8.8 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version=~ "^1\.[68]") {
  if(version_in_range(version:version, test_version:"1.6.0", test_version2:"1.6.15")||
     version_in_range(version:version, test_version:"1.8.0", test_version2:"1.8.7")) {
    security_message(port:0, data:"The target host was found to be vulnerable");
    exit(0);
  }
}
