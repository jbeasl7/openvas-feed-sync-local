# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkmk:checkmk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125208");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-16 07:17:51 +0000 (Fri, 16 May 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-22 20:26:01 +0000 (Fri, 22 Aug 2025)");

  script_cve_id("CVE-2025-32917");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk < 2.2.0p42, 2.3.x < 2.3.0p32, 2.4.x < 2.4.0b7 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_checkmk_server_http_detect.nasl");
  script_mandatory_keys("checkmk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The jar_signature agent plugin (configured by the 'Signatures
  of certificates in JAR files' bakery rule) prepends JAVA_HOME/bin to the PATH environment
  variable. A user with write permission to that directory could replace legitimate commands with
  their own malicious scripts and execute them as root.");

  script_tag(name:"affected", value:"Checkmk versions prior to 2.2.0p42, 2.3.x prior to 2.3.0p32 and
  2.4.x prior to 2.4.0b7.");

  script_tag(name:"solution", value:"Update to version 2.2.0p42, 2.3.0p32, 2.4.0b7 or
  later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/17985");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.2.0p42" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0p42", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.3.0", test_version_up: "2.3.0p32" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.0p32", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.4.0", test_version_up: "2.4.0b7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.0b7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
