# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800375");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6472");
  script_name("Wireshark Denial of Service Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32840");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2008-07.html");

  script_tag(name:"impact", value:"Successful attacks may cause the application to crash via unspecified
  attack vectors.");

  script_tag(name:"affected", value:"Wireshark version prior to 1.0.5 on Linux.");

  script_tag(name:"insight", value:"Error in the WLCCP and SMTP dissector allows to exploit by triggering the
  execution into an infinite loop through specially crafted packets.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.5.");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"1.0.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.0.5", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
