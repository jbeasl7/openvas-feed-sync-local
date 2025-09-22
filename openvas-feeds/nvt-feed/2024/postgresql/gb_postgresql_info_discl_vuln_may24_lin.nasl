# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152210");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2024-05-14 02:23:31 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 16:17:31 +0000 (Wed, 12 Feb 2025)");

  script_cve_id("CVE-2024-4317");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 14.x < 14.12, 15.x < 15.7, 16.x < 16.3 Information Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl",
                      "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Missing authorization in PostgreSQL built-in views pg_stats_ext
  and pg_stats_ext_exprs allows an unprivileged database user to read most common values and other
  statistics from CREATE STATISTICS commands of other users. The most common values may reveal
  column values the eavesdropper could not otherwise read or results of functions they cannot
  execute.");

  script_tag(name:"affected", value:"PostgreSQL version 14.x prior to 14.12, 15.x prior to 15.7 and
  16.x prior to 16.3.");

  script_tag(name:"solution", value:"Update to version 14.12, 15.7, 16.3 or later.

  Note: Installing an unaffected version only fixes fresh PostgreSQL installations, namely those
  that are created with the initdb utility after installing that version. Current PostgreSQL
  installations will remain vulnerable until additional mitigation steps have been applied. Please
  see the referenced vendor advisory for further information.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-163-157-1412-1315-and-1219-released-2858/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2024-4317/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
