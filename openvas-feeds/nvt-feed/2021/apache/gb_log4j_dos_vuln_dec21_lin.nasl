# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:log4j";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117845");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-12-18 11:22:05 +0000 (Sat, 18 Dec 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-30 16:22:00 +0000 (Thu, 30 Dec 2021)");

  script_cve_id("CVE-2021-45105");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Log4j 2.x < 2.17.0 DoS Vulnerability (Linux/Unix, Dec 2021) - Version Check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_log4j_consolidation.nasl");
  script_mandatory_keys("apache/log4j/ssh-login/detected");

  script_tag(name:"summary", value:"Apache Log4j is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Log4j2 did not protect from uncontrolled recursion from
  self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a
  Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map
  (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a
  StackOverflowError that will terminate the process.");

  script_tag(name:"affected", value:"Apache Log4j versions 2.0.x through 2.16.0.");

  script_tag(name:"solution", value:"Update to version 2.3.1, 2.12.3, 2.17.0 or later.");

  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-p6xc-xr62-6r2g");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"2.0", test_version2:"2.3.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.3.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"2.4.0", test_version2:"2.12.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.12.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version =~ "^2\.16" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.17.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
