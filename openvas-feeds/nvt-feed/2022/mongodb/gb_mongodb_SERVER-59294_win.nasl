# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147597");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2022-02-07 03:14:08 +0000 (Mon, 07 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-09 19:24:00 +0000 (Wed, 09 Feb 2022)");

  script_cve_id("CVE-2021-32036");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB DoS Vulnerability (SERVER-59294) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user without any specific authorizations may
  be able to repeatedly invoke the features command where at a high volume may lead to resource
  depletion or generate high lock contention.");

  script_tag(name:"impact", value:"This may result in denial of service and in rare cases could
  result in id field collisions.");

  script_tag(name:"affected", value:"MongoDB version 2.x through 4.2.16, 4.4.x through 4.4.9 and
  5.x through 5.0.3.");

  script_tag(name:"solution", value:"Update to version 4.2.18, 4.4.10, 5.0.4 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-59294");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "4.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.18");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.0", test_version2: "4.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
