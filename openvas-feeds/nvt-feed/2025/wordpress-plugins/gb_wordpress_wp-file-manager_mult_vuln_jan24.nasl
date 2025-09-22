# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webdesi9:file_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124736");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-02-10 08:08:12 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-13 16:15:08 +0000 (Wed, 13 Mar 2024)");

  script_cve_id("CVE-2023-6825", "CVE-2024-0761");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress File Manager Plugin < 7.2.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-file-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'File Manager' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-6825: Directory Traversal via the target parameter in the
  mk_file_folder_manager_action_callback_shortcode function.

  - CVE-2024-0761: Sensitive Information Exposure due to insufficient randomness in the backup
  filenames, which use a timestamp plus 4 random digits.");

  script_tag(name:"affected", value:"WordPress File Manager plugin prior to version 7.2.2.");

  script_tag(name:"solution", value:"Update to version 7.2.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e1b4077a-2b56-4fd9-9a19-d758dacb08a4/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e04c3f89-55c7-4d8c-9a11-a16cc64079e9/");

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
