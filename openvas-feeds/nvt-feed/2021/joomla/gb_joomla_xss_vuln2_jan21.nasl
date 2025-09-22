# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145127");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2021-01-13 04:50:46 +0000 (Wed, 13 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-19 15:59:00 +0000 (Tue, 19 Jan 2021)");

  script_cve_id("CVE-2021-23124");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 3.9.0 - 3.9.23 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Lack of escaping in mod_breadcrumbs aria-label attribute allows XSS attacks.");

  script_tag(name:"affected", value:"Joomla! versions 3.9.0 - 3.9.23.");

  script_tag(name:"solution", value:"Update to version 3.9.24 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/837-20210102-core-xss-in-mod-breadcrumbs-aria-label-attribute.html");

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

if (version_in_range(version: version, test_version: "3.9.0", test_version2: "3.9.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.24", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
