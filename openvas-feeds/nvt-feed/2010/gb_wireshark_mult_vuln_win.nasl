# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801432");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-2995");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Wireshark Multiple Vulnerabilities (wnpa-sec-2010-08) - Windows");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2010-08.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.10.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of
  service, execution of arbitrary code.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.9
  Wireshark version 0.10.8 to 1.0.14");
  script_tag(name:"insight", value:"Multiple flaws are due to error in 'sigcomp-udvm.c' and an
  off-by-one error, which could be exploited to execute arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.0.15 or 1.2.10 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");
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

if(version_in_range(version:version, test_version:"0.10.8", test_version2:"1.0.14")||
   version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.9")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
