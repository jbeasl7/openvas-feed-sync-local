# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801757");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1140", "CVE-2011-1141");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark Multiple Vulnerabilities (Mar 2011) - Windows");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-03.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-04.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.15.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark 1.0.x
  Wireshark version 1.2.0 through 1.2.14
  Wireshark version 1.4.0 through 1.4.3");
  script_tag(name:"insight", value:"The flaws are due to

  - Multiple stack consumption vulnerabilities in the
    'dissect_ms_compressed_string' and 'dissect_mscldap_string functions'

  - Error in 'epan/dissectors/packet-ldap.c' which allows attackers to cause
    a denial of service via a long LDAP filter string or an LDAP filter string
    containing many elements.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.4 or 1.2.15");
  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.0", test_version2:"1.0.16")||
   version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.14")||
   version_in_range(version:version, test_version:"1.4.0", test_version2:"1.4.3")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
