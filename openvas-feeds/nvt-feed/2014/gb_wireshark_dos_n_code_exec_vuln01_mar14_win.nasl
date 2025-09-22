# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804331");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2014-2281", "CVE-2014-2283", "CVE-2014-2299");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-03-14 10:57:29 +0530 (Fri, 14 Mar 2014)");
  script_name("Wireshark Denial of Service and Code Execution Vulnerabilities-01 (Mar 2014) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to denial of service (DoS) and remote code
  execution (RCE) vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an error within the NFS dissector
(epan/dissectors/packet-nfs.c), RLC dissector (epan/dissectors/packet-rlc) and
MPEG parser (wiretap/mpeg.c).");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
and compromise a vulnerable system.");
  script_tag(name:"affected", value:"Wireshark version 1.8.x before 1.8.13 and 1.10.x before 1.10.6 on Windows.");
  script_tag(name:"solution", value:"Update to version 1.8.13 or 1.10.6 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57265");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66072");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
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

if(vers =~ "^1\.(8|10)") {
  if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.12") ||
     version_in_range(version:vers, test_version:"1.10.0", test_version2:"1.10.5")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"1.8.13 / 1.10.6", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
