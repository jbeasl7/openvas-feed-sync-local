# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149054");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2023-01-03 03:06:18 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 04:49:00 +0000 (Thu, 05 Jan 2023)");

  script_cve_id("CVE-2022-41765", "CVE-2022-41766", "CVE-2022-41767");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.8, 1.36.x < 1.37.5, 1.38.x < 1.38.3 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-41765: HTMLUserTextField exposes existence of hidden users

  - CVE-2022-41766: The message 'alreadyrolled' can leak revision deleted user name

  - CVE-2022-41767: reassignEdits doesn't update results in an IP range check on
  Special:Contributions");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.8, version 1.36.x, 1.37.x
  through 1.37.4 and 1.38.x through 1.38.2.");

  script_tag(name:"solution", value:"Update to version 1.35.8, 1.37.5, 1.38.3 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/SPYFDCGZE7KJNO73ET7QVSUXMHXVRFTE/");

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

if (version_is_less(version: version, test_version: "1.35.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.36.0", test_version2: "1.37.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.37.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.38.0", test_version2: "1.38.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.38.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
