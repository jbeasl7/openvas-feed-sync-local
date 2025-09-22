# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113000");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-09-19 08:36:42 +0200 (Tue, 19 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-18 16:30:00 +0000 (Mon, 18 Sep 2017)");

  script_cve_id("CVE-2017-14238", "CVE-2017-14239", "CVE-2017-14240", "CVE-2017-14241",
                "CVE-2017-14242");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr 6.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SQL injection in admin/menus/edit.php via the menuId parameter

  - SQL injection in don/list.php via the statut parameter

  - XSS in htdocs/admin/company.php via the (1) CompanyName, (2) CompanyAddress, (3) CompanyZip,
  (4) CompanyTown, (5) Fax, (6) EMail, (7) Web, (8) ManagingDirectors, (9) Note, (10) Capital,
  (11) ProfId1, (12) ProfId2, (13) ProfId3, (14) ProfId4, (15) ProfId5, or (16) ProfId6 parameter

  - XSS in htdocs/admin/menus/edit.php via the Title parameter

  - Sensititve information disclosure in document.php via the file parameter");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute
  arbitrary HTML and script code in a user's browser session in the context of a vulnerable site
  and to cause SQL Injection attacks to gain sensitive information.");

  script_tag(name:"affected", value:"Dolibarr version 6.0.0.");

  script_tag(name:"solution", value:"Update to version 6.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/commit/d26b2a694de30f95e46ea54ea72cc54f0d38e548");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version:version, test_version:"6.0.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.0.1", install_path:location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
