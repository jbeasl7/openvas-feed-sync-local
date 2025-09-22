# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804912");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2014-6426", "CVE-2014-6425");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-09-24 14:29:16 +0530 (Wed, 24 Sep 2014)");

  script_name("Wireshark DOS Vulnerability-02 (Sep 2014) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to:

  - Error in the get_quoted_string and get_unquoted_string functions
    in epan/dissectors/packet-cups.c in the CUPS dissector.

  - The dissect_hip_tlv function in epan/dissectors/packet-hip.c
    in the HIP dissector does not properly handle a NULL tree.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.12.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-15.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69863");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69866");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-16.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(version_is_equal(version:vers, test_version:"1.12.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 1.12.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
