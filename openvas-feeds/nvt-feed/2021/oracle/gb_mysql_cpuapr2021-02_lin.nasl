# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145795");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-04-21 05:44:36 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  # nb: From the vendor advisory:
  # The patch for CVE-2021-23841 also addresses CVE-2021-23840.
  # The patch for CVE-2021-3449 also addresses CVE-2021-3450.
  # The patch for CVE-2021-3450 also addresses CVE-2021-3449.
  script_cve_id("CVE-2021-3449", "CVE-2021-3450", "CVE-2021-23840", "CVE-2021-23841", "CVE-2021-2307",
                "CVE-2021-2304", "CVE-2021-2180", "CVE-2021-2194", "CVE-2021-2166", "CVE-2021-2179",
                "CVE-2021-2226", "CVE-2021-2169", "CVE-2021-2146", "CVE-2021-2174", "CVE-2021-2171",
                "CVE-2021-2162");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server <= 5.7.33 / 8.0 <= 8.0.23 Security Update (cpuapr2021) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 5.7.33 and prior and 8.0 through 8.0.23.");

  script_tag(name:"solution", value:"Update to version 5.7.34, 8.0.24 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuapr2021");

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

if (version_is_less_equal(version: version, test_version: "5.7.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
