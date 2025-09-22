# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:commons_beanutils";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154592");
  script_version("2025-05-30T15:42:19+0000");
  script_tag(name:"last_modification", value:"2025-05-30 15:42:19 +0000 (Fri, 30 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-30 02:54:09 +0000 (Fri, 30 May 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-48734");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Commons BeanUtils 1.x < 1.11.0, 2.0.0-M1 < 2.0.0-M2 Improper Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apache_commons_consolidation.nasl");
  script_mandatory_keys("apache/commons/beanutils/detected");

  script_tag(name:"summary", value:"The Apache Commons BeanUtils library is prone to an improper
  access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A special BeanIntrospector class was added in version 1.9.2.
  This can be used to stop attackers from using the declared class property of Java enum objects to
  get access to the classloader. However this protection was not enabled by default.
  PropertyUtilsBean (and consequently BeanUtilsBean) now disallows declared class level property
  access by default.");

  script_tag(name:"affected", value:"Apache Commons BeanUtils version 1.x prior to 1.11.0 and
  2.0.0-M1.");

  script_tag(name:"solution", value:"Update to version 1.11.0, 2.0.0-M2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/s0hb3jkfj5f3ryx6c57zqtfohb0of1g9");

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

if (version_is_less(version: version, test_version: "1.11.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: tolower(version), test_version_lo: "2.0.0.m1", test_version_up: "2.0.0.m2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0-M2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
