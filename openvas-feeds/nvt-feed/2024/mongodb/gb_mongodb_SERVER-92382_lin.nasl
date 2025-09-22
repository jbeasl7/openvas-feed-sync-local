# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153224");
  script_version("2024-11-08T15:39:48+0000");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-22 07:35:22 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-07 15:38:32 +0000 (Thu, 07 Nov 2024)");

  script_cve_id("CVE-2024-8305");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB DoS Vulnerability (SERVER-92382) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"prepareUnique index may cause secondaries to crash due to
  incorrect enforcement of index constraints on secondaries, where in extreme cases may cause
  multiple secondaries crashing leading to no primaries.");

  script_tag(name:"affected", value:"MongoDB version 6.0.x prior to 6.0.17, 7.0.x prior to 7.0.13
  and 7.3.x prior to 7.3.4.");

  script_tag(name:"solution", value:"Update to version 6.0.17, 7.0.13, 7.3.4 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-92382");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.17");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.13");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.3", test_version_up: "7.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
