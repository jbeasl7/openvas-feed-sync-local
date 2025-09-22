# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126721");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-05-16 07:50:07 +0000 (Thu, 16 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-3374");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB DoS Vulnerability (SERVER-75601) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated user can trigger a fatal assertion in the
  server while generating ftdc diagnostic metrics due to attempting to build a BSON object that
  exceeds certain memory sizes.");

  # nb: 5.1.x through 5.3.x and 6.1.x through 6.2.x are not mentioned as affected in the advisory
  # but are already EOL and thus assumed to be affected as well but just not mentioned by the vendor
  # due to their EOL status.
  script_tag(name:"affected", value:"MongoDB version 5.x prior to 5.0.17, 5.1.x prior to 6.0.6 and
  6.1.x prior to 6.3.2.");

  script_tag(name:"solution", value:"Update to version 5.0.17, 6.0.6, 6.3.2 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-75601");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.17");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "6.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
