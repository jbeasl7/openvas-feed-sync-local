# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113707");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-06-18 09:30:48 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 16:15:00 +0000 (Wed, 02 Jun 2021)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-11022", "CVE-2020-11023", "CVE-2020-13625", "CVE-2020-14295");

  script_name("Cacti <= 1.2.12 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-11022, CVE-2020-11023: jQuery XSS vulnerabilities require vendor package update

  - No CVE: Lack of escaping on some pages can lead to XSS exposure

  - CVE-2020-13625: Update PHPMailer to 6.1.6

  - CVE-2020-14295: SQL Injection vulnerability due to input validation failure when editing colors

  - No CVE: Lack of escaping on template import can lead to XSS exposure");

  script_tag(name:"impact", value:"- CVE-2020-14295: Successful exploitation would allow an
  authenticated attacker to read or modify sensitive information or execute arbitrary code on the
  target machine.");

  script_tag(name:"affected", value:"Cacti through version 1.2.12.");

  script_tag(name:"solution", value:"Update to version 1.2.13 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3622");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/releases/tag/release%2F1.2.13");

  exit(0);
}

CPE = "cpe:/a:cacti:cacti";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.2.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.13", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
