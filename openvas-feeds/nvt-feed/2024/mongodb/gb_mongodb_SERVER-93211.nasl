# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114741");
  script_version("2024-09-20T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-09-20 05:05:37 +0000 (Fri, 20 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-08-07 14:12:56 +0000 (Wed, 07 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 20:46:04 +0000 (Thu, 19 Sep 2024)");

  script_cve_id("CVE-2024-7553");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Local Privilege Escalation Vulnerability (SERVER-93211)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect validation of files loaded from a local untrusted
  directory may allow local privilege escalation if the underlying operating systems is Windows.
  This may result in the application executing arbitrary behaviour determined by the contents of
  untrusted files.");

  # nb: 5.1.x through 5.3.x, 6.1.x through 6.3.x and 7.1.x through 7.2.x are not mentioned as
  # affected in the advisory but are already EOL and thus assumed to be affected as well but just
  # not mentioned by the vendor due to their EOL status.
  script_tag(name:"affected", value:"MongoDB version 5.x prior to 5.0.27, 6.0.x prior to 6.0.16,
  6.1.x prior to 7.0.12 and 7.1.x prior to 7.3.3.

  Only environments with Windows as the underlying operating system is affected by this issue.");

  script_tag(name:"solution", value:"Update to version 5.0.27, 6.0.16, 7.0.12, 7.3.3 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-93211");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/CDRIVER-5650");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/PHPC-2369");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.27");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "6.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "7.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.12");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
