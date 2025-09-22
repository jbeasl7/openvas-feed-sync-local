# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adminer:adminer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145993");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-05-21 03:50:07 +0000 (Fri, 21 May 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-25 20:26:00 +0000 (Tue, 25 May 2021)");

  script_cve_id("CVE-2021-29625");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adminer 4.6.1 < 4.8.1 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adminer_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("adminer/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Adminer is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Users of MySQL, MariaDB, PgSQL and SQLite are affected. XSS is
  in most cases prevented by strict CSP in all modern browsers. The only exception is when Adminer
  is using a pdo_ extension to communicate with the database (it is used if the native extensions
  are not enabled).");

  script_tag(name:"affected", value:"Adminer version 4.6.1 through 4.8.0.

  Note: In modern browsers with strict CSP only version 4.7.8 through 4.8.0 is affected.");

  script_tag(name:"solution", value:"Update to version 4.8.1 or later.");

  # nb: There are currently some inconsistencies on the advisory related to the affected versions so
  # https://github.com/vrana/adminer/issues/1151 was created to get some clarification.
  script_xref(name:"URL", value:"https://github.com/vrana/adminer/security/advisories/GHSA-2v82-5746-vwqc");
  script_xref(name:"URL", value:"https://sourceforge.net/p/adminer/bugs-and-features/797/");
  script_xref(name:"URL", value:"https://github.com/vrana/adminer/commit/4043092ec2c0de2258d60a99d0c5958637d051a7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version:"4.6.1", test_version2: "4.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
