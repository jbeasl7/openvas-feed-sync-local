# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webdesi9:file_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128099");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-20 04:24:42 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 17:16:46 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2024-0761");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress File Manager Plugin < 7.2.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-file-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'File Manager' is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sensitive information exposure due to insufficient randomness in
  the backup filenames, which use a timestamp plus 4 random digits.");

  script_tag(name:"impact", value:"An unauthenticated attacker can extract sensitive data including
  site backups in configurations where the .htaccess file in the directory does not block access.");

  script_tag(name:"affected", value:"WordPress File Manager plugin prior to version 7.2.2.");

  script_tag(name:"solution", value:"Update to version 7.2.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-file-manager/file-manager-721-sensitive-information-exposure-via-backup-filenames");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "7.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
