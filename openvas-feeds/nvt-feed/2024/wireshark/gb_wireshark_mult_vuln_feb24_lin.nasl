# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128009");
  script_version("2024-07-24T05:06:37+0000");
  script_cve_id("CVE-2024-24478", "CVE-2024-24476", "CVE-2024-24479");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-04-18 11:00:00 +0000 (Thu, 18 Apr 2024)");
  script_name("Wireshark < 4.2.0 DoS Vulnerabilities");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An issue in Wireshark function dissect_bgp_open of file packet-bgp.c.

  - A buffer overflow vulnerability in ws_manuf_lookup_str of file pan/addr_resolv.c.

  - A buffer overflow vulnerability in format_fractional_part_nsecs of file wsutil/to_str.c.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation may allow
  remote attackers to perform denial of service on an affected system.");

  script_tag(name:"affected", value:"Wireshark versions prior to 4.2.0.");

  script_tag(name:"solution", value:"Update to version 4.2.0 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/1047524396/e82c55147cd3cb62ef20cbdb0ec83694");
  script_xref(name:"URL", value:"https://gist.github.com/1047524396/369ba0ccffe255cf8142208b6142be2b");
  script_xref(name:"URL", value:"https://gist.github.com/1047524396/c50ad17e9a1a18990043a7cd27814c78");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version: version, test_version: "4.2.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.0", install_path: path );
  security_message( port: 0 , data: report );
  exit( 0 );
}

exit( 99 );
