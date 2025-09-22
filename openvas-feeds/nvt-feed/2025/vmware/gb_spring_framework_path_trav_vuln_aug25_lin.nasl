# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:spring_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155180");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-08-20 04:11:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2025-41242");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware Spring Framework <= 5.3.43, 6.0.0 - 6.0.29, 6.1.0 - 6.1.21, 6.2.0 - 6.2.9 Path Traversal Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vmware_spring_framework_consolidation.nasl");
  script_mandatory_keys("vmware/spring/framework/ssh-login/detected");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to a path traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Spring Framework MVC applications can be vulnerable to a path
  traversal when deployed on a non-compliant Servlet container.

  An application can be vulnerable when all the following are true:

  - the application is deployed as a WAR or with an embedded Servlet container

  - the Servlet container does not reject suspicious sequences

  - the application serves static resources with Spring resource handling");

  script_tag(name:"affected", value:"VMware Spring Framework version 5.3.43 and prior, 6.0.0
  through 6.0.29, 6.1.0 through 6.1.21 and 6.2.0 through 6.2.9.");

  script_tag(name:"solution", value:"Update to version 5.3.44, 6.1.22, 6.2.10 or later.");

  script_xref(name:"URL", value:"https://spring.io/security/cve-2025-41242");
  script_xref(name:"URL", value:"https://spring.io/blog/2025/08/14/spring-framework-6-2-10-release-fixes-cve-2025-41242");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.3.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.44", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.1.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
