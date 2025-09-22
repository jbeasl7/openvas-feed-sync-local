# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804051");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2013-7113");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-12-30 20:54:19 +0530 (Mon, 30 Dec 2013)");
  script_name("Wireshark BSSGP Dissector Denial of Service Vulnerability-02 (Dec 2013) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 1.10.4 or later.");

  script_tag(name:"insight", value:"Flaw is due to an error within the BSSGP dissector.");

  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.4 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a Denial of Service.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56097");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64413");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2013-66.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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
  if(version_in_range(version:vers, test_version:"1.10.0", test_version2:"1.10.3")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"1.10.0 - 1.10.3", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
