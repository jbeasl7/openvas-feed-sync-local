# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144178");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-06-29 06:51:18 +0000 (Mon, 29 Jun 2020)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-23 17:43:00 +0000 (Wed, 23 Dec 2020)");

  script_cve_id("CVE-2020-15005");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Information Disclosure Vulnerability (Jun 2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Private wikis behind a caching server using the img_auth.php image
  authorization security feature may have had their files cached publicly, so any unauthorized user could view
  them. This occurs because Cache-Control and Vary headers were mishandled.");

  script_tag(name:"affected", value:"MediaWiki versions before 1.31.8, 1.33.4 and 1.34.2.");

  script_tag(name:"solution", value:"Update to version 1.31.8, 1.33.4, 1.34.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/wikitech-l/2020-June/093535.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.31.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.32", test_version2: "1.33.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.33.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.34.0", test_version2: "1.34.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.34.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
