# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113639");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-02-17 14:07:49 +0000 (Mon, 17 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 12:15:00 +0000 (Wed, 15 Jul 2020)");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-8492");

  script_name("Python 2.7.x <= 2.7.17, 3.5 <= 3.5.9, 3.6.x <= 3.6.10, 3.7.x <= 3.7.6, 3.8.x <= 3.8.1 Regular Expression Denial of Service (ReDoS) Vulnerability - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"Python is prone to a Regular Expression Denial of Service
  (ReDoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target
  host.");

  script_tag(name:"insight", value:"The AbstractBasicAuthHandler class of the urllib.request
  module uses an inefficient regular expression (catastrophic backtracking) which can be
  exploited by an attacker to cause a denial of service.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash
  the application.");

  script_tag(name:"affected", value:"Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through
  3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1.");

  script_tag(name:"solution", value:"Update to version 3.5.10, 3.6.11, 3.7.8, 3.8.3 or 3.9.0
  respectively.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue39503");
  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/urllib-basic-auth-Nregex.html");

  exit(0);
}

CPE = "cpe:/a:python:python";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.5.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.10", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.11", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.7.0", test_version2: "3.7.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.8.0", test_version2: "3.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
