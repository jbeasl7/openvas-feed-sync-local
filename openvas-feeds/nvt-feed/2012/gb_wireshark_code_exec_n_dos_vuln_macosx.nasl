# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802626");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2011-3360", "CVE-2011-3266");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-05-02 12:12:12 +0530 (Wed, 02 May 2012)");
  script_name("Wireshark Code Execution and Denial of Service Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-15.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49377");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49528");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-13.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6136");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to execute arbitrary script
  in the context of the affected application and denial of service condition.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.9 and 1.6.x before 1.6.2 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error related to Lua scripts, which allows local users to
    gain privileges via a Trojan horse Lua script in an unspecified directory.

  - An error in 'IKEv1' protocol dissector and 'proto_tree_add_item()', when
    add more than 1000000 items to a proto_tree, that will cause a denial of
    service.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.9, 1.6.2 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to code execution and denial of service vulnerabilities.");
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

if(version_in_range (version:version, test_version:"1.6.0", test_version2:"1.6.1") ||
   version_in_range (version:version, test_version:"1.4.0", test_version2:"1.4.8")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
