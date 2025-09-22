# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:liferay:liferay_portal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143436");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-02-04 02:17:21 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-23 18:15:00 +0000 (Mon, 23 Nov 2020)");

  script_cve_id("CVE-2020-7934");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Liferay Portal 7.1.0 - 7.2.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_liferay_consolidation.nasl");
  script_mandatory_keys("liferay/portal/detected");

  script_tag(name:"summary", value:"Liferay Portal is prone to an authenticated cross-site
  scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In LifeRay Portal CE the First Name, Middle Name, and Last
  Name fields for user accounts in MyAccountPortlet are all vulnerable to a persistent XSS issue.
  Any user can modify these fields with a particular XSS payload, and it will be stored in the
  database. The payload will then be rendered when a user utilizes the search feature to search for
  other users (i.e., if a user with modified fields occurs in the search results).");

  script_tag(name:"affected", value:"Liferay Portal versions 7.1.0 - 7.2.1.");

  script_tag(name:"solution", value:"Update to version 7.3.0 or later.");

  script_xref(name:"URL", value:"https://semanticbits.com/liferay-portal-authenticated-xss-disclosure/");

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

if (version_in_range(version: version, test_version: "7.1.0", test_version2: "7.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
