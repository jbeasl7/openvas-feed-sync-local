# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:theforeman:foreman";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106416");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-8639");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman 1.11.x < 1.13.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_http_detect.nasl");
  script_mandatory_keys("foreman/detected");

  script_tag(name:"summary", value:"Foreman is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an organization or location is created with a name
  containing HTML, then the administrator-only Settings page will render the HTML as part of a
  dropdown menu. This may permit a stored XSS attack if an organization/location with HTML in the
  name is created, when an administrator attempts to change the default organization/location
  settings.");

  script_tag(name:"affected", value:"Foreman versions 1.11.x through 1.12.4.");

  script_tag(name:"solution", value:"Update to version 1.13.0 or later.");

  script_xref(name:"URL", value:"https://theforeman.org/security.html#2016-8639");

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

if (version_in_range(version: version, test_version: "1.11.0", test_version2: "1.12.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.13.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
