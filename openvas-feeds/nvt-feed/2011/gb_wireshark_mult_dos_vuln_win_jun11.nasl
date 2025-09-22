# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802200");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174",
                "CVE-2011-2175");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44449/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48066");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-07.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-08.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.2.x before 1.2.17 and 1.4.x before 1.4.7.");
  script_tag(name:"insight", value:"- An error in the DICOM dissector can be exploited to cause an infinite loop
    when processing certain malformed packets.

  - An error when processing a Diameter dictionary file can be exploited to
    cause the process to crash.

  - An error when processing a snoop file can be exploited to cause the process
    to crash.

  - An error when processing compressed capture data can be exploited to cause
    the process to crash.

  - An error when processing a Visual Networks file can be exploited to cause
    the process to crash.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.2.17 or 1.4.7 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range (version:version, test_version:"1.2.0", test_version2:"1.2.16") ||
   version_in_range (version:version, test_version:"1.4.0", test_version2:"1.4.6")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
