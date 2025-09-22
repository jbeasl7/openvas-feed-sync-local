# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkmk:checkmk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126755");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2024-03-22 10:00:26 +0000 (Fri, 22 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-04 16:47:59 +0000 (Wed, 04 Dec 2024)");

  script_cve_id("CVE-2024-0638", "CVE-2024-28824");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk < 2.1.0p41, 2.2.x < 2.2.0p24, 2.3.x < 2.3.0b4 Multiple Privilege Escalation Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_checkmk_server_http_detect.nasl");
  script_mandatory_keys("checkmk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to multiple privilege escalation
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-0638: The agent plugins mk_oracle, mk_oracle.ps1 and mk_oracle_crs were vulnerable to
  privilege escalation to root by the oracle user. A malicious oracle user could replace a binary
  (e.g. sqlplus) with another script and put it in the corresponding directory. The script would be
  executed by the root user.

  - CVE-2024-28824: The informix database monitoring plugin would previously eval statements parsed
  from $INFORMIXDIR/bin/onstat. Since the plugin is usually run as root, this could cause
  statements injected in $INFORMIXDIR/bin/onstat to be run as root as well. By adding scripts named
  the same as other functionality found in $PATH to $INFORMIXDIR/bin, $PATH functionality could
  also be overshadowed and the custom executed as root. Finally, $INFORMIXDIR/bin/onstat would be
  executed as root, allowing a substituted script to be run with elevated privileges.");

  script_tag(name:"affected", value:"Checkmk versions prior to 2.1.0p41, 2.2.x prior to
  2.2.0p24 and 2.3.x prior to 2.3.0b4.");

  script_tag(name:"solution", value:"Update to version 2.1.0p41, 2.2.0p24, 2.3.0b4 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/16232");
  script_xref(name:"URL", value:"https://checkmk.com/werk/16198");

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

if( version_is_less( version: version, test_version: "2.1.0p41" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p41", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0p24" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0p24", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.3.0", test_version_up: "2.3.0b4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.0b4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
