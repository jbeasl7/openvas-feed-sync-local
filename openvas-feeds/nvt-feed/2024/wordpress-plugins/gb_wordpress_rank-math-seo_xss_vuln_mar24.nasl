# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rankmath:seo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103047");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-05-13 16:13:12 +0000 (Mon, 13 May 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 19:15:35 +0000 (Tue, 09 Apr 2024)");

  script_cve_id("CVE-2024-2536");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Rank Math SEO with AI SEO Tools Plugin < 1.0.215 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");

  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/seo-by-rank-math/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Rank Math SEO with AI SEO Tools' is prone
   to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate and escape some of its shortcode
   ttributes before outputting them back in a page/post where the shortcode is embed, which could
   allow users with the contributor role and above to perform stored cross-site scripting attacks.");

  script_tag(name:"impact", value:"Attackers with contributor-level and above permissions are able
   to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected
   page.");

  script_tag(name:"affected", value:"WordPress Rank Math SEO with AI SEO Tools plugin prior to
   version 1.0.215.");

  script_tag(name:"solution", value:"Update to version 1.0.215 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/seo-by-rank-math/rank-math-seo-with-ai-seo-tools-10214-authenticatedcontributor-stored-cross-site-scripting-via-howto-block-attributes");

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

if( version_is_less( version: version, test_version: "1.0.215" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.215", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
