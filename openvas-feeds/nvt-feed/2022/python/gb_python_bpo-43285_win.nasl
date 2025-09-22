# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126133");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-09-01 09:00:11 +0200 (Thu, 01 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 13:31:00 +0000 (Mon, 29 Aug 2022)");

  script_cve_id("CVE-2021-4189");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.14, 3.7.x < 3.7.11, 3.8.x < 3.8.9, 3.9.x < 3.9.3 (bpo-43285) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This flaw allows an attacker to set up a malicious FTP server,
  that can trick FTP clients into connecting back to a given IP address and port.");

  script_tag(name:"affected", value:"Python prior to version 3.6.14, versions 3.7.x prior to 3.7.11,
  3.8.x prior to 3.8.9 and 3.9.x prior to 3.9.3.");

  script_tag(name:"solution", value:"Update to version 3.6.14, 3.7.11, 3.8.9, 3.9.3 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/ftplib-pasv.html");
  script_xref(name:"Advisory-ID", value:"bpo-43285");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.6.14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.14", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.7.0", test_version_up: "3.7.11" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7.11", install_path: location );
  security_message(port: port, data: report);
  exit(0);
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.8.0", test_version_up: "3.8.9" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.9", install_path: location );
  security_message(port: port, data: report);
  exit(0);
}

if( version_in_range_exclusive( version: version, test_version_lo: "3.9.0", test_version_up: "3.9.3" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.3", install_path: location );
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );
