# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rankmath:seo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128102");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 16:13:12 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-24 16:44:13 +0000 (Mon, 24 Feb 2025)");

  script_cve_id("CVE-2024-13227", "CVE-2024-13229");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Rank Math SEO with AI SEO Tools Plugin < 1.0.236 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");

  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/seo-by-rank-math/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Rank Math SEO with AI SEO Tools' is prone
   to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-13227: The plugin is vulnerable to XSS attacks due to insufficient
  input sanitization and output escaping on user supplied attributes.

  - CVE-2024-13229: The plugin is vulnerable to unauthorized loss of data due to a missing
  capability check on the update_metadata() function.");

  script_tag(name:"affected", value:"WordPress Rank Math SEO with AI SEO Tools plugin prior to
   version 1.0.236.");

  script_tag(name:"solution", value:"Update to version 1.0.236 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/24df10fb-5143-478e-90f0-27f604ad43ee?");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/5776f689-56dd-413d-b02d-5551b97dd5eb?");

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

if( version_is_less( version: version, test_version: "1.0.236" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.236", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
