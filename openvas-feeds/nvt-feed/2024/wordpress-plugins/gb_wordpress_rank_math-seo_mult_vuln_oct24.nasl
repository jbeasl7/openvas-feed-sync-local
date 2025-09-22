# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rankmath:seo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128066");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-25 16:13:12 +0000 (Mon, 25 Nov 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-05 12:15:03 +0000 (Sat, 05 Oct 2024)");

  script_cve_id("CVE-2024-9161", "CVE-2024-9314");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Rank Math SEO with AI SEO Tools Plugin < 1.0.229 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");

  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/seo-by-rank-math/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Rank Math SEO with AI SEO Tools' is prone
   to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-9161: The plugin is vulnerable to unauthorized modification and loss of data due to a
    missing capability check on the 'update_metadata' function that can cause a loss of access to
    the administrator dashboard for any registered users, including administrators.

  - CVE-2024-9314: The plugin is vulnerable to PHP Object Injection via deserialization of
    untrusted input 'set_redirections' function that can allow an attacker to delete arbitrary files
    , retrieve sensitive data, or execute arbitrary code.");

  script_tag(name:"affected", value:"WordPress Rank Math SEO with AI SEO Tools plugin through
   version 1.0.228.");

  script_tag(name:"solution", value:"Update to version 1.0.229 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/7df39a64-76c5-4ebe-a271-44bd147a3a86?source=cve");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/af5ed47e-f183-4e72-a916-15020e2bc91e?source=cve");

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

if( version_is_less( version: version, test_version: "1.0.229" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.229", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );