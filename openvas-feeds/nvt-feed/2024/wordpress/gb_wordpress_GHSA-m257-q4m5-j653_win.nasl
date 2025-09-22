# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152048");
  script_version("2024-04-05T15:38:49+0000");
  script_tag(name:"last_modification", value:"2024-04-05 15:38:49 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-05 09:39:55 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");

  script_cve_id("CVE-2024-31211");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress RCE Vulnerability (GHSA-m257-q4m5-j653) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to a remote code execution (RCE)
  vulnerability in 'WP_HTML_Token'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unserialization of instances of the WP_HTML_Token class allows
  for code execution via its __destruct() magic method.");

  script_tag(name:"affected", value:"WordPress version 6.4.0 through 6.4.1.");

  script_tag(name:"solution", value:"Update to version 6.4.2 or later.");

  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-m257-q4m5-j653");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.4", test_version_up: "6.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
