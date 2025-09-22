# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128168");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-07-22 02:44:16 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-54352");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("WordPress Information Disclosure Vulnerability (Jul 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress allows remote attackers to guess titles of private and
  draft posts via pingback.ping XML-RPC requests.

  NOTE: The vendor is not changing this behavior.");

  script_tag(name:"affected", value:"WordPress versions 3.5.x through 6.8.2.");

  script_tag(name:"solution", value:"No known solution is available as of 23rd July, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-585c-5qcq-7fgc");
  script_xref(name:"URL", value:"https://www.imperva.com/blog/beware-a-threat-actor-could-steal-the-titles-of-your-private-and-draft-wordpress-posts/");

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

if (version_in_range(version: version, test_version: "3.5", test_version2: "6.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
