# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webdesi9:file_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124739");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-02-10 08:08:12 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-06 20:28:28 +0000 (Tue, 06 Nov 2018)");

  script_cve_id("CVE-2018-16363");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress File Manager Plugin < 3.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-file-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'File Manager' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Lack of sanitisation in the lang parameter in the admin
  dashboard could allow attacker to perform reflected XSS attacks against logged in
  administrators.");

  script_tag(name:"affected", value:"WordPress File Manager plugin prior to version 3.0.");

  script_tag(name:"solution", value:"Update to version 3.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/65e4849b-6517-400d-884f-65234f58ab0c/");

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

if (version_is_less(version: version, test_version: "3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
