# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152189");
  script_version("2024-05-10T15:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-10 15:38:34 +0000 (Fri, 10 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-10 02:59:14 +0000 (Fri, 10 May 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-03 06:15:14 +0000 (Fri, 03 May 2024)");

  script_cve_id("CVE-2024-4439");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress XSS Vulnerability (Apr 2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress Core is vulnerable to a stored cross-site scripting
  via user display names in the Avatar block due to insufficient output escaping on the display
  name. This makes it possible for authenticated attackers, with contributor-level access and
  above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an
  injected page. In addition, it also makes it possible for unauthenticated attackers to inject
  arbitrary web scripts in pages that have the comment block present and display the comment
  author's avatar.");

  script_tag(name:"affected", value:"WordPress version 6.5 and prior.");

  script_tag(name:"solution", value:"Update to version 6.0.8, 6.1.6, 6.2.5, 6.3.4, 6.4.4, 6.5.2 or
  later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2024/04/wordpress-6-5-2-maintenance-and-security-release/");

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

if (version_is_less(version: version, test_version: "6.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2", test_version_up: "6.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.3", test_version_up: "6.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.4", test_version_up: "6.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.5", test_version_up: "6.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
