# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801435");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-2993");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Wireshark 'IPMI dissector' Denial of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-08.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jul/1024269.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.10.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial of service.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.9");
  script_tag(name:"insight", value:"The flaw is due to an error in the handling of 'IPMI dissector',
  which could be exploited to go into an infinite loop.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.2.10 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
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

if(version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.9")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"1.2.0 - 1.2.9", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
