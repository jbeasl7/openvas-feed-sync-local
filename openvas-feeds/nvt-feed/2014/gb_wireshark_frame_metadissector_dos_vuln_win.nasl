# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804665");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2014-4020");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-07-07 10:00:15 +0530 (Mon, 07 Jul 2014)");
  script_name("Wireshark 'Frame Metadissector' Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an error in 'dissect_frame' function in
  epan/dissectors/packet-frame.c within the frame metadissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct a DoS
  (Denial of Service) attack.");

  script_tag(name:"affected", value:"Wireshark version 1.10.0 through 1.10.7 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.10.8 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68044");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2014-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.10") {
  if(version_in_range(version:vers, test_version:"1.10.0", test_version2:"1.10.7")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"1.10.0 - 1.10.7", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
