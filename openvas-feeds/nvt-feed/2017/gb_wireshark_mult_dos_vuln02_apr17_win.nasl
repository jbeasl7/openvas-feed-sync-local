# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811001");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2017-7748", "CVE-2017-7746", "CVE-2017-7747", "CVE-2017-7745",
                "CVE-2017-7705", "CVE-2017-7702", "CVE-2017-7703", "CVE-2017-7701",
                "CVE-2017-7700");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-19 15:07:50 +0530 (Wed, 19 Apr 2017)");
  script_name("Wireshark Multiple DoS Vulnerabilities-02 (Apr 2017) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in WSP dissector, SLSK dissector, SIGCOMP dissector,
    RPC over RDMA dissector, WBXML dissector, BGP dissector and NetScaler file
    parser which could go into an infinite loop triggered by packet injection or
    a malformed capture file.

  - Multiple errors in PacketBB dissector and IMAP dissector triggered by packet
    injection or a malformed capture file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to crash resulting in denial-of-service
  condition.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 through 2.2.5
  and 2.0.0 through 2.0.11 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.2.6 or
  2.2.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97635");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97627");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97633");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97636");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97632");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97631");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-19.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-18.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-20.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-15.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-13.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-12.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-16.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-14.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^2\.") {
  if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.5")) {
    fix = "2.2.6";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.0.11")) {
    fix = "2.0.12";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
