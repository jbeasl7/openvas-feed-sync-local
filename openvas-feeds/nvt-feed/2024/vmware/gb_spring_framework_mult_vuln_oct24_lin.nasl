# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:spring_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153222");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2024-10-22 07:12:57 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-22 15:42:22 +0000 (Tue, 22 Oct 2024)");

  script_cve_id("CVE-2024-38819", "CVE-2024-38820");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware Spring Framework 5.3.0 < 5.3.41, 6.0.x < 6.0.25, 6.1.x < 6.1.14 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_spring_framework_consolidation.nasl");
  script_mandatory_keys("vmware/spring/framework/ssh-login/detected");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-38819: Path traversal in functional web frameworks

  - CVE-2024-38820: DataBinder case sensitive match exception");

  script_tag(name:"affected", value:"VMware Spring Framework version 5.3.x through 5.3.40, 6.0.x
  through 6.0.24 and 6.1.x through 6.1.13.");

  script_tag(name:"solution", value:"Update to version 5.3.41, 6.0.25, 6.1.14 or later.");

  script_xref(name:"URL", value:"https://spring.io/blog/2024/10/17/spring-framework-cve-2024-38819-and-cve-2024-38820-published");
  script_xref(name:"URL", value:"https://spring.io/security/cve-2024-38819");
  script_xref(name:"URL", value:"https://spring.io/security/cve-2024-38820");
  script_xref(name:"URL", value:"https://github.com/masa42/CVE-2024-38819-POC");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.3.0", test_version_up: "5.3.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.0.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1.0", test_version_up: "6.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
