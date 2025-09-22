# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:snapcreek:duplicator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124142");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-08-23 08:05:00 +0100 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-23 18:59:00 +0000 (Tue, 23 Aug 2022)");

  script_cve_id("CVE-2022-2552");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Duplicator Plugin < 1.4.7.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/duplicator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Duplicator' is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Duplicator WordPress plugin does not authenticate or
  authorize visitors before displaying information about the system such as server software, php
  version and full file system path to the site.");

  script_tag(name:"affected", value:"WordPress Duplicator plugin version prior to 1.4.7.1.");

  script_tag(name:"solution", value:"Update to version 1.4.7.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/6b540712-fda5-4be6-ae4b-bd30a9d9d698");
  script_xref(name:"URL", value:"https://github.com/SecuriTrust/CVEsLab/tree/main/CVE-2022-2552");

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

if( version_is_less( version: version, test_version: "1.4.7.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.7.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
