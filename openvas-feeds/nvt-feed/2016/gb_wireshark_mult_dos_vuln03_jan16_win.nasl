# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806947");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2015-8716", "CVE-2015-8715", "CVE-2015-8714", "CVE-2015-8713",
                "CVE-2015-8719", "CVE-2015-8717", "CVE-2015-8712");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:29:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-11 11:59:19 +0530 (Mon, 11 Jan 2016)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities-03 (Jan 2016) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - 'init_t38_info_conv' function in 'epan/dissectors/packet-t38.c'
  script in the T.38 dissector does not ensure that a conversation exists.

  - 'epan/dissectors/packet-alljoyn.c' in the AllJoyn dissector
  does not check for empty arguments.

  - 'dissect_dcom_OBJREF' function in 'epan/dissectors/packet-dcom.c'
  script in the DCOM dissecto does not initialize a certain IPv4 data structure.

  - 'epan/dissectors/packet-umts_fp.c' script in the UMTS FP dissector
  does not properly reserve memory for channel ID mappings.

  - 'dissect_dns_answer' function in 'epan/dissectors/packet-dns.c'
  script in the DNS dissector mishandles the EDNS0 Client Subnet option.

  - 'dissect_sdp' function in 'epan/dissectors/packet-sdp.c' script
  in the SDP dissector does not prevent use of a negative media count.

  - 'dissect_hsdsch_channel_info' function in 'epan/dissectors/packet-umts_fp.c'
  script in the UMTS FP dissector does not validate the number of PDUs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.9
  on Windows.");

  script_tag(name:"solution", value:"Update to version 1.12.9 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2015-33.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-32.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9887");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11607");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"1.12.0", test_version2:"1.12.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.12.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
