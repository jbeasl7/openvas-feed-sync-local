# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128157");
  script_version("2025-08-25T05:40:31+0000");
  script_tag(name:"last_modification", value:"2025-08-25 05:40:31 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-06-20 10:41:19 +0000 (Fri, 20 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-22 18:59:49 +0000 (Fri, 22 Aug 2025)");

  script_cve_id("CVE-2025-49575", "CVE-2025-49579");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki >= 2.4.2 < 3.3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-49575: Multiple system messages are inserted into the CommandPaletteFooter as raw HTML,
  allowing anybody who can edit those messages to insert arbitrary HTML into the DOM.

  - CVE-2025-49579: All system messages in menu headings using the Menu.mustache template are
  inserted as raw HTML, allowing anybody who can edit those messages to insert arbitrary HTML into
  the DOM.");

  script_tag(name:"affected", value:"MediaWiki version through 2.4.2 prior to 3.3.1.");

  script_tag(name:"solution", value:"Update to version 3.3.1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-g3cp-pq72-hjpv");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-4c2h-67qq-vm87");

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

if (version_in_range(version: version, test_version: "2.4.2", test_version2: "3.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
