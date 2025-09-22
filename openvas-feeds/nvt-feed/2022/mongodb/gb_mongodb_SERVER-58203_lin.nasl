# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147978");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2022-04-13 04:35:09 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-20 13:39:00 +0000 (Wed, 20 Apr 2022)");

  script_cve_id("CVE-2021-32040");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB DoS Vulnerability (SERVER-58203, SERVER-59299, SERVER-60218) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It may be possible to have an extremely long aggregation
  pipeline in conjunction with a specific stage/operator and cause a stack overflow due to the size
  of the stack frames used by that stage.");

  script_tag(name:"impact", value:"If an attacker could cause such an aggregation to occur, they
  could maliciously crash MongoDB in a DoS attack.");

  script_tag(name:"affected", value:"MongoDB prior to version 4.2.16, 4.4.x through 4.4.10 and
  5.x through 5.0.3.");

  script_tag(name:"solution", value:"Update to version 4.2.16, 4.4.11, 5.0.4 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-58203");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-59299");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-60218");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
