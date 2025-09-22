# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adminer:adminer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145371");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2021-02-12 04:14:20 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 12:50:00 +0000 (Thu, 24 Jun 2021)");

  script_cve_id("CVE-2020-35572", "CVE-2021-21311");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adminer 4.7.0 < 4.7.9 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adminer_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("adminer/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Adminer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-35572: XSS via the history parameter

  - CVE-2021-21311: SSRF on error page of Elasticsearch and ClickHouse");

  script_tag(name:"affected", value:"Adminer versions 4.7.0 through 4.7.8.");

  script_tag(name:"solution", value:"Update to version 4.7.9 or later.");

  script_xref(name:"URL", value:"https://github.com/vrana/adminer/security/advisories/GHSA-9pgx-gcph-mpqr");
  script_xref(name:"URL", value:"https://sourceforge.net/p/adminer/bugs-and-features/775/");
  script_xref(name:"URL", value:"https://github.com/vrana/adminer/security/advisories/GHSA-x5r2-hj5c-8jx6");
  script_xref(name:"URL", value:"https://sourceforge.net/p/adminer/news/2021/02/adminer-479-released/");

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

if (version_in_range(version: version, test_version:"4.7.0", test_version2: "4.7.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
