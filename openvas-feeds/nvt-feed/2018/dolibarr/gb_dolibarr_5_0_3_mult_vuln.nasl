# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113154");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-04-11 13:19:33 +0200 (Wed, 11 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-16 14:27:00 +0000 (Wed, 16 May 2018)");

  script_cve_id("CVE-2017-9838", "CVE-2017-9839");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr <= 5.0.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Dolibarr ERP/CRM is affected by multiple reflected cross-site scripting (XSS) vulnerabilities:
  index.php (leftmenu parameter), core/ajax/box.php (PATH_INFO), product/stats/card.php
  (type parameter), holiday/list.php (month_create, month_start, and month_end parameters), and
  don/card.php (societe, lastname, firstname, address, zipcode, town, and email parameters).

  - Dolibarr ERP/CRM is affected by SQL injection via product/stats/card.php (type parameter).");

  script_tag(name:"affected", value:"Dolibarr version 5.0.3 and prior.");

  script_tag(name:"solution", value:"Update to version 5.0.4 or later.");

  script_xref(name:"URL", value:"https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-010");

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

if( version_is_less( version: version, test_version: "5.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
