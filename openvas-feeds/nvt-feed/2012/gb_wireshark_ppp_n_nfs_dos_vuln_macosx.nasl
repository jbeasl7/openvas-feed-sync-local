# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802899");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2012-4048", "CVE-2012-4049");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-07-27 10:00:50 +0530 (Fri, 27 Jul 2012)");
  script_name("Wireshark PPP And NFS Dissector Denial of Service Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.14,
  1.6.x before 1.6.9 and 1.8.x before 1.8.1 on Mac OS X.");

  script_tag(name:"insight", value:"Errors within the PPP and 'epan/dissectors/packet-nfs.c' in the NFS
  dissector can be exploited to cause a crash via specially crafted packets.");

  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.14, 1.6.9, 1.8.1 or later.");

  script_tag(name:"summary", value:"Wireshark is prone to denial of service vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49971");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54649");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027293");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-11.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-12.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7436");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-nfs.c?r1=43576&r2=43575&pathrev=43576");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.4.0", test_version2:"1.4.13") ||
   version_in_range(version:version, test_version:"1.6.0", test_version2:"1.6.8") ||
   version_is_equal(version:version, test_version:"1.8.0")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
