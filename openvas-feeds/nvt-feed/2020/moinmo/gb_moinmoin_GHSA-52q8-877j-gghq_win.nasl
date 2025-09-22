# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moinmo:moinmoin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144913");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-11-11 04:12:12 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-24 17:20:00 +0000 (Tue, 24 Nov 2020)");

  script_cve_id("CVE-2020-25074", "CVE-2020-15275");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MoinMoin < 1.9.11 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moinmoinWiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MoinMoin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The cache action in action/cache.py allows directory traversal through a crafted HTTP request (CVE-2020-25074)

  - Malicious SVG attachment causing stored cross-site scripting (XSS) (CVE-2020-15275)");

  script_tag(name:"impact", value:"- An attacker who can upload attachments to the wiki can use this to achieve
  remote code execution (CVE-2020-25074)

  - An attacker with write permissions can upload an SVG file that contains malicious javascript. This javascript
    will be executed in a user's browser when the user is viewing that SVG file on the wiki. (CVE-2020-15275)");

  script_tag(name:"affected", value:"MoinMoin prior to version 1.9.11.");

  script_tag(name:"solution", value:"Update to version 1.9.11 or later.");

  script_xref(name:"URL", value:"https://github.com/moinwiki/moin-1.9/security/advisories/GHSA-52q8-877j-gghq");
  script_xref(name:"URL", value:"https://github.com/moinwiki/moin-1.9/security/advisories/GHSA-4q96-6xhq-ff43");

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

if (version_is_less(version: version, test_version: "1.9.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
