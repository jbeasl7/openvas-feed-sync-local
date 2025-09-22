# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805322");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2015-0564", "CVE-2015-0563", "CVE-2015-0562", "CVE-2015-0561",
                "CVE-2015-0560", "CVE-2015-0559");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-01-14 08:43:33 +0530 (Wed, 14 Jan 2015)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities -01 (Jan 2015) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within the SMTP dissector.

  - An error within the DEC DNA Routing Protocol dissector.

  - An error within the LPP dissector.

  - Two errors within the WCCP dissector.

  - An error when decypting TLS/SSL sessions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct multiple denial-of-service attacks.");

  script_tag(name:"affected", value:"Wireshark 1.10.x before 1.10.12 and
  1.12.x before 1.12.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.10.12,
  1.12.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71916");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71919");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71918");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-01.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-02.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-04.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"1.10.0", test_version2:"1.10.11") ||
   version_in_range(version:vers, test_version:"1.12.0", test_version2:"1.12.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.10.12 / 1.12.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
