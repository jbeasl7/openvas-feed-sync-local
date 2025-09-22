# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112446");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-12-04 10:37:00 +0100 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-27 21:06:00 +0000 (Thu, 27 Dec 2018)");

  script_cve_id("CVE-2018-1002000", "CVE-2018-1002001", "CVE-2018-1002002", "CVE-2018-1002003",
                "CVE-2018-1002004", "CVE-2018-1002005", "CVE-2018-1002006", "CVE-2018-1002007",
                "CVE-2018-1002008", "CVE-2018-1002009");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Arigato Autoresponder and Newsletter Plugin < 2.5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/bft-autoresponder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Arigato Autoresponder and Newsletter' is
  prone to blind SQL injection (SQLi) and multiple reflected cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Arigato Autoresponder and Newsletter plugin through
  version 2.5.1.8.");

  script_tag(name:"solution", value:"Update the plugin to version 2.5.2 or later.");

  script_xref(name:"URL", value:"http://www.vapidlabs.com/advisory.php?v=203");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/bft-autoresponder/#developers");

  exit(0);
}

CPE = "cpe:/a:kibokolabs:arigato_autoresponder_and_newsletter";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
