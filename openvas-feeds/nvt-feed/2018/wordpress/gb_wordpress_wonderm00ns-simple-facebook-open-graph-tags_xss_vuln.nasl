# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112287");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-05-16 15:20:00 +0200 (Wed, 16 May 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-19 16:21:00 +0000 (Tue, 19 Jun 2018)");

  script_cve_id("CVE-2018-0579");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Open Graph for Facebook, Google+ and Twitter Card Tags Plugin < 2.2.4.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wonderm00ns-simple-facebook-open-graph-tags/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Open Graph' is prone to a cross-site
  scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Open Graphs plugin before version 2.2.4.1.");

  script_tag(name:"solution", value:"Update to version 2.2.4.1 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN08386386/index.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wonderm00ns-simple-facebook-open-graph-tags/#developers");

  exit(0);
}

CPE = "cpe:/a:webdados:open_graph_for_facebook%2c_google%2b_and_twitter_card_tags";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.2.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.4.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
