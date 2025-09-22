# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:spring_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153454");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2024-11-18 09:03:51 +0000 (Mon, 18 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-38828");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware Spring Framework < 5.3.42 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_spring_framework_consolidation.nasl");
  script_mandatory_keys("vmware/spring/framework/smb-login/detected");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Spring MVC controller methods with an @RequestBody byte[]
  method parameter are vulnerable to a DoS attack.");

  script_tag(name:"affected", value:"VMware Spring Framework version 5.3.41 and prior.");

  script_tag(name:"solution", value:"Update to version 5.3.42 or later.");

  script_xref(name:"URL", value:"https://spring.io/blog/2024/11/15/spring-framework-cve-2024-38828-published");
  script_xref(name:"URL", value:"https://spring.io/security/cve-2024-38828");

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

if (version_is_less(version: version, test_version: "5.3.42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.42", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
