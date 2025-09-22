# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151889");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-08 06:45:27 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-11 16:56:35 +0000 (Tue, 11 Mar 2025)");

  script_cve_id("CVE-2024-1351");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Certificate Validation Vulnerability (SERVER-72839) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a certificate validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Under certain configurations of --tlsCAFile and tls.CAFile,
  MongoDB Server may skip peer certificate validation which may result in untrusted connections to
  succeed. This may effectively reduce the security guarantees provided by TLS and open connections
  that should have been closed due to failing certificate validation.

  Required Configuration: A server process will allow incoming connections to skip peer certificate
  validation if the server process was started with TLS enabled (net.tls.mode set to allowTLS,
  preferTLS, or requireTLS) and without a net.tls.CAFile configured.");

  # nb: 5.1.x through 5.3.x and 6.1.x through 6.3.x are not mentioned as affected in the advisory
  # but have been released long after 3.2.6, are already EOL and thus assumed to be affected as well
  # but just not mentioned by the vendor due to their EOL status.
  script_tag(name:"affected", value:"MongoDB version 3.2.6 through 4.4.28, 5.x through 5.0.24,
  5.1.x through 6.0.13 and 6.1.x through 7.0.5.");

  script_tag(name:"solution", value:"Update to version 4.4.29, 5.0.25, 6.0.14, 7.0.6 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-72839");
  script_xref(name:"URL", value:"https://www.mongodb.com/docs/manual/release-notes/4.4/#4.4.29---february-28--2024");
  script_xref(name:"URL", value:"https://www.mongodb.com/docs/v5.0/release-notes/5.0/#5.0.25---february-28--2024");
  script_xref(name:"URL", value:"https://www.mongodb.com/docs/v6.0/release-notes/6.0/#6.0.14---feb-28--2024");
  script_xref(name:"URL", value:"https://www.mongodb.com/docs/manual/release-notes/7.0/#7.0.6---feb-28--2024");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.6", test_version_up: "4.4.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.29");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.25");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "6.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "7.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
