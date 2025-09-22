# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113616");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-12-09 13:29:42 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-01 17:06:00 +0000 (Tue, 01 Oct 2019)");

  script_cve_id("CVE-2019-16685", "CVE-2019-16686", "CVE-2019-16687", "CVE-2019-16688");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr <= 9.0.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS in a User Note section in note.php.

  - Stored XSS via a User Group Description section to card.php.

  - Stored XSS in an Email Template section to mails_templates.php.

  - Stored XSS in a User Profile in a Signature section to card.php.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  permanently inject arbitrary JavaScript or HTML into the site.");

  script_tag(name:"affected", value:"Dolibarr version 9.0.5 and prior.");

  script_tag(name:"solution", value:"Update to version 10.0.0 or later.");

  script_xref(name:"URL", value:"http://verneet.com/cve-2019-16685");
  script_xref(name:"URL", value:"http://verneet.com/cve-2019-16686");
  script_xref(name:"URL", value:"http://verneet.com/cve-2019-16687");
  script_xref(name:"URL", value:"http://verneet.com/cve-2019-16688");

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

if( version_is_less_equal( version: version, test_version: "9.0.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
