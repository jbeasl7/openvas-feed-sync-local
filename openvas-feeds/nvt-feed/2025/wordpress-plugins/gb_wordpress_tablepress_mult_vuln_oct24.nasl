# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tablepress:tablepress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124729");
  script_version("2025-03-10T05:35:40+0000");
  script_tag(name:"last_modification", value:"2025-03-10 05:35:40 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-02-10 08:08:12 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-07 17:06:07 +0000 (Fri, 07 Mar 2025)");

  script_cve_id("CVE-2024-9595", "CVE-2024-45293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress TablePress Plugin < 2.4.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/tablepress/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'TablePress' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-9595: The TablePress is vulnerable to Stored Cross-Site Scripting via the
  table cell content due to insufficient input sanitization and output escaping.

  - CVE-2024-45293: The security scanner that prevents XXE attacks in the XLSX reader can
  be bypassed by slightly modifying the XML structure, utilizing white spaces. On servers
  that allow users to upload their own Excel (XLSX) sheets, Server files, and sensitive
  information can be disclosed by providing a crafted sheet.");

  script_tag(name:"affected", value:"WordPress TablePress plugin prior to version 2.4.3.");

  script_tag(name:"solution", value:"Update to version 2.4.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/tablepress/tablepress-242-authenticated-author-stored-cross-site-scripting");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/tablepress/phpspreadsheet-library-230-xxe-injection");

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

if( version_is_less(version: version, test_version: "2.4.3" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
