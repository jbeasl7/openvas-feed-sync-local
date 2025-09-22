# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805805");
  script_version("2025-03-12T05:38:19+0000");
  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-22 15:08:18 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"creation_date", value:"2015-06-24 15:36:26 +0530 (Wed, 24 Jun 2015)");
  script_name("PostgreSQL Multiple Vulnerabilities (May 2015) - Linux");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-942-937-9211-9116-and-9020-released-1587/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122160721/http://www.securityfocus.com/bid/74787");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-3165: Double 'free' after authentication timeout

  - CVE-2015-3166: Unanticipated errors from the standard library

  - CVE-2015-3167: pgcrypto has multiple error messages for decryption with an incorrect key");

  script_tag(name:"affected", value:"PostgreSQL versions prior to 9.0.20, 9.1.x prior to 9.1.16,
  9.2.x prior to 9.2.11, 9.3.x prior to 9.3.7 and 9.4.x prior to 9.4.2.");

  script_tag(name:"solution", value:"Update to version 9.0.20, 9.1.16, 9.2.11, 9.3.7, 9.4.2 or
  later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(version_is_less(version:vers, test_version:"9.0.20") ||
   version_in_range(version:vers, test_version:"9.1", test_version2:"9.1.15") ||
   version_in_range(version:vers, test_version:"9.2", test_version2:"9.2.10") ||
   version_in_range(version:vers, test_version:"9.3", test_version2:"9.3.6") ||
   version_in_range(version:vers, test_version:"9.4", test_version2:"9.4.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
