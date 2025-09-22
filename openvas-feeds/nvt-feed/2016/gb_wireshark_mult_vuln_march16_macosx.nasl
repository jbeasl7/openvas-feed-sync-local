# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807449");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2016-2532", "CVE-2016-2531", "CVE-2016-2523", "CVE-2016-2521",
                "CVE-2016-4421", "CVE-2016-4418", "CVE-2016-4417");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-03-03 13:23:19 +0530 (Thu, 03 Mar 2016)");
  script_name("Wireshark Multiple Vulnerabilities (Mar 2016) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The 'dissect_llrp_parameters' function in 'epan/dissectors/packet-llrp.c'
    script in the LLRP dissector does not limit the recursion depth.

  - The Off-by-one error in 'epan/dissectors/packet-rsl.c' script in the RSL
    dissector.

  - The 'dnp3_al_process_object' function in 'epan/dissectors/packet-dnp.c' script
    in the DNP3 dissector

  - An untrusted search path vulnerability in the Application class
    'ui/qt/wireshark_application.cpp' script.

  - Multiple errors in 'epan/dissectors/packet-ber.c' script in the ASN.1 BER dissector.

  - An Off-by-one error in 'epan/dissectors/packet-gsm_abis_oml.c' script in the
    GSM A-bis OML dissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack and local users to gain privileges.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.10
  and 2.0.x before 2.0.2 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 1.12.10 or
  2.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-01.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-03.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-10.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-11.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-18.html");

  script_category(ACT_GATHER_INFO);
  script_family("General");
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

if(version_in_range(version:vers, test_version:"1.12.0", test_version2:"1.12.9")) {
  fix = "1.12.10";
  VULN = TRUE ;
}

else if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.0.1")) {
  fix = "2.0.2";
  VULN = TRUE ;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
