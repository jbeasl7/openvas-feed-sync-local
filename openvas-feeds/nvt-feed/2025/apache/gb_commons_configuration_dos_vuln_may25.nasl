# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:commons_configuration";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154571");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-26 05:19:16 +0000 (Mon, 26 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2025-46392");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Commons Configuration 1.x DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_commons_consolidation.nasl");
  script_mandatory_keys("apache/commons/configuration/detected");

  script_tag(name:"summary", value:"The Apache Commons Configuration library is prone to a denial
  of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There are a number of issues in Apache Commons Configuration
  1.x that allow excessive resource consumption when loading untrusted configurations or using
  unexpected usage patterns.");

  script_tag(name:"affected", value:"Apache Commons Configuration version 1.x.

  The Apache Commons Configuration team does not intend to fix these issues in 1.x. Apache Commons
  Configuration 1.x is still safe to use in scenario's where you only load trusted
  configurations.");

  script_tag(name:"solution", value:"Update to version 2.0.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/y1pl0mn3opz6kwkm873zshjdxq3dwq5s");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0", test_version_up: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
