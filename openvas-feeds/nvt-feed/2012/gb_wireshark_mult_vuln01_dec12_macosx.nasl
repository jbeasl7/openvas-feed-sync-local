# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803134");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2012-4296", "CVE-2012-4293", "CVE-2012-4292", "CVE-2012-4291",
                "CVE-2012-4290", "CVE-2012-4289", "CVE-2012-4288", "CVE-2012-4285");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-12-28 14:53:05 +0530 (Fri, 28 Dec 2012)");
  script_name("Wireshark Multiple Vulnerabilities-01 (Dec 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50276/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55035");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027404");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-13.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-20.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-23.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-17.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-15.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to denial of service or
  to consume excessive CPU resources.");
  script_tag(name:"affected", value:"Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10 and
  1.8.x before 1.8.2 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - A division by zero error within the DCP ETSI dissector, an error within
    the STUN dissector and EtherCAT Mailbox dissector can be exploited to
    cause a crash.

  - An error within the RTPS2 dissector can be exploited to cause a buffer
    overflow.

  - An error within the STUN dissector can be exploited to cause a crash.

  - An error within the CIP dissector can be exploited to exhaust memory.

  - An error within the CTDB dissector, AFP dissector and XTP dissector can be
    exploited to trigger an infinite loop and consume excessive CPU resources.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.15, 1.6.10 or 1.8.2 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.4.0", test_version2:"1.4.14") ||
   version_in_range(version:version, test_version:"1.6.0", test_version2:"1.6.9") ||
   version_in_range(version:version, test_version:"1.8.0", test_version2:"1.8.1")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
