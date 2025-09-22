# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800396");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-04-20 14:33:23 +0200 (Mon, 20 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1210", "CVE-2009-1266", "CVE-2009-1267", "CVE-2009-1268",
                "CVE-2009-1269");
  script_name("Wireshark Multiple Unspecified Vulnerabilities (Apr 2009) - Windows");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34457");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34778");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34542");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Apr/1022027.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation could result in denial of service condition.");
  script_tag(name:"affected", value:"Wireshark version 0.9.6 to 1.0.6 on Windows");
  script_tag(name:"insight", value:"- Error exists while processing PN-DCP packet with format string specifiers
    in PROFINET/DCP (PN-DCP) dissector.

  - Error in unknown impact and attack vectors.

  - Error in Lightweight Directory Access Protocol (LDAP) dissector when
    processing unknown attack vectors.

  - Error in Check Point High-Availability Protocol (CPHAP) when processing
    crafted FWHA_MY_STATE packet.

  - An error exists while processing malformed Tektronix .rf5 file.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.7.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple unspecified vulnerabilities.");
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

if(version_is_less(version:version, test_version:"1.0.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.0.7", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
