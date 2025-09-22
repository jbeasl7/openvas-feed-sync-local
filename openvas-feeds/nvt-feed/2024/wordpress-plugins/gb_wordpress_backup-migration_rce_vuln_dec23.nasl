# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:backupbliss:backup_migration";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124638");
  script_version("2024-10-31T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-10-31 05:05:48 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-04-22 09:10:45 +0000 (Mon, 22 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-15 11:15:47 +0000 (Fri, 15 Dec 2023)");

  script_cve_id("CVE-2023-6553");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Backup Migration Plugin < 1.3.8 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/backup-backup/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Backup Migration' is prone to a remote
  code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote Code Execution (RCE) via the /includes/backup-heart.php
  file. This is due to an attacker being able to control the values passed to an include, and
  subsequently leverage that to achieve remote code execution.");

  script_tag(name:"affected", value:"WordPress Backup Migration plugin prior to version 1.3.8.");

  script_tag(name:"solution", value:"Update to version 1.3.8 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/backup-backup/backup-migration-137-unauthenticated-remote-code-execution");

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

if( version_is_less( version: version, test_version: "1.3.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
