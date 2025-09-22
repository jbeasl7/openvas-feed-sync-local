# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:spring_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154733");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-06-13 05:04:00 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:P/A:N");

  script_cve_id("CVE-2025-41234");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware Spring Framework 6.0.5 - 6.0.28, 6.1.0 - 6.1.20, 6.2.0 - 6.2.7 RFD Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vmware_spring_framework_consolidation.nasl");
  script_mandatory_keys("vmware/spring/framework/smb-login/detected");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to a reflected file
  download (RFD) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Spring Framework an application is vulnerable to a reflected
  file download (RFD) attack when it sets a 'Content-Disposition' header with a non-ASCII charset,
  where the filename attribute is derived from user-supplied input.");

  # nb: From the advisory:
  # > Older, unsupported versions are not affected
  script_tag(name:"affected", value:"VMware Spring Framework version 6.0.5 through 6.0.28, 6.1.0
  through 6.1.20 and 6.2.0 through 6.2.7.");

  script_tag(name:"solution", value:"Update to version 6.0.29, 6.1.21, 6.2.8 or later.");

  script_xref(name:"URL", value:"https://spring.io/security/cve-2025-41234");
  script_xref(name:"URL", value:"https://spring.io/blog/2025/06/12/spring-framework-6-1-21-and-6-2-8-releases-fix-cve-2025-41234");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.5", test_version_up: "6.0.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1.0", test_version_up: "6.1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
