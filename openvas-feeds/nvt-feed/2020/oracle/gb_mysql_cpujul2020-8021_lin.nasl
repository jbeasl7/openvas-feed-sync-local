# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144293");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-07-21 08:47:24 +0000 (Tue, 21 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-1967", "CVE-2020-14663", "CVE-2020-14678", "CVE-2020-14697", "CVE-2020-14591",
                "CVE-2020-14539", "CVE-2020-14680", "CVE-2020-14619", "CVE-2020-14576", "CVE-2020-14643",
                "CVE-2020-14651", "CVE-2020-14568", "CVE-2020-14623", "CVE-2020-14540", "CVE-2020-14575",
                "CVE-2020-14620", "CVE-2020-14624", "CVE-2020-14656", "CVE-2020-14547", "CVE-2020-14597",
                "CVE-2020-14614", "CVE-2020-14654", "CVE-2020-14632", "CVE-2020-14631", "CVE-2020-14586",
                "CVE-2020-14702", "CVE-2020-14641", "CVE-2020-14559", "CVE-2020-14553", "CVE-2020-14633",
                "CVE-2020-14634", "CVE-2020-14725");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.0 <= 8.0.20 Security Update (cpujul2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 8.0 through 8.0.20.");

  script_tag(name:"solution", value:"Update to version 8.0.21 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2020.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujul2020");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
