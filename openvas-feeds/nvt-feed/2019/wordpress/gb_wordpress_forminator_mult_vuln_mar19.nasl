# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112529");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-03-05 11:34:00 +0100 (Tue, 05 Mar 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-18 15:42:00 +0000 (Thu, 18 May 2023)");

  script_cve_id("CVE-2019-9567", "CVE-2019-9568");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Forminator Plugin < 1.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/forminator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Forminator' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-9567: cross-site scripting (XSS) via a custom input field of a poll.

  - CVE-2019-9568: SQL injection (SQLi) via the wp-admin/admin.php?page=forminator-entries entry[]
  parameter if the attacker has the delete permission.");

  script_tag(name:"affected", value:"WordPress Forminator plugin prior to version 1.6.");

  script_tag(name:"solution", value:"Update to version 1.6 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/forminator/#developers");
  script_xref(name:"URL", value:"https://security-consulting.icu/blog/2019/02/wordpress-forminator-persistent-xss-blind-sql-injection/");
  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2019/02/05/4");

  exit(0);
}

CPE = "cpe:/a:incsub:forminator";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
