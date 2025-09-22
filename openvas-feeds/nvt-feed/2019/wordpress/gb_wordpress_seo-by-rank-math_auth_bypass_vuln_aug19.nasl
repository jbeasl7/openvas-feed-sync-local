# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rankmath:seo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113484");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-08-29 12:54:45 +0000 (Thu, 29 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 16:10:00 +0000 (Mon, 18 Apr 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-14786");

  script_name("WordPress Rank Math SEO Plugin <= 1.0.27 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/seo-by-rank-math/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Rank Math SEO' is prone to an authentication
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Non-Admin users can reset the settings via the
  wp-admin/admin-post.php reset-cmb parameter.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  perform actions he would normally not be allowed to.");

  script_tag(name:"affected", value:"WordPress Rank Math SEO plugin through version 1.0.27.");

  script_tag(name:"solution", value:"Update to version 1.0.27.1 or later.");

  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2019/06/20/authenticated-settings-reset-vulnerability-in-rank-math-seo/");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9375");
  script_xref(name:"URL", value:"https://rankmath.com/changelog/");

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

if( version_is_less( version: version, test_version: "1.0.27.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.27.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
