# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801553");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-3445");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Wireshark BER Dissector Stack Consumption Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/10/12/1");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/10/01/10");
  script_xref(name:"URL", value:"http://xorl.wordpress.com/2010/10/15/cve-2010-3445-wireshark-asn-1-ber-stack-overflow/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash the application.");
  script_tag(name:"affected", value:"Wireshark version 1.4.x before 1.4.1 and 1.2.x before 1.2.12");
  script_tag(name:"insight", value:"The flaw is due to stack consumption  in the 'dissect_ber_unknown()'
  function in 'epan/dissectors/packet-ber.c' in the BER dissector, which allows
  remote attackers to cause a denial of service (NULL pointer dereference and
  crash) via a long string in an unknown 'ASN.1/BER' encoded packet.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.4.1 or 1.2.12 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to stack consumption vulnerability.");
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

if(version_is_equal(version:version, test_version:"1.4.0") ||
   version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.11")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
