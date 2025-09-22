# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808290");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2016-6507", "CVE-2016-6504");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:33:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-08-09 12:20:26 +0530 (Tue, 09 Aug 2016)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities-03 (Aug 2016) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in 'epan/dissectors/packet-mmse.c' script could cause the
    MMSE dissector to go into a long loop.

  - The 'epan/dissectors/packet-ncp2222.inc' script in the NDS dissector
    does not properly maintain a ptvc data structure.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.13
  on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 1.12.13
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/28/3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92164");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-43.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-40.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.12.0", test_version2:"1.12.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.12.13", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
