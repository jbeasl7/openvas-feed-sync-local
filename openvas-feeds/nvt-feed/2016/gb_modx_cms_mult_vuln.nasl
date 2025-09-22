# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:modx:revolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106459");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-12-09 11:42:44 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-14 20:04:00 +0000 (Thu, 14 Nov 2019)");

  script_cve_id("CVE-2016-10037", "CVE-2016-10038", "CVE-2016-10039");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX CMS 2.x < 2.5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_http_detect.nasl");
  script_mandatory_keys("modx/cms/detected");

  script_tag(name:"summary", value:"MODX CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist::

  - Critical settings visible in MODx.config

  - Local file inclusion/traversal/manipulation

  - Unauthenticated access to processors

  - Path traversal in modConnectorResponse action param");

  script_tag(name:"impact", value:"An attacker access or manipulate files on the system.");

  script_tag(name:"affected", value:"MODX CMS Revolutions version 2.x through 2.5.1.");

  script_tag(name:"solution", value:"Update to version 2.5.2 or later.");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/modxcms/revolution/v2.5.2-pl/core/docs/changelog.txt");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13170");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13176");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13175");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13173");

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

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
