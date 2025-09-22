# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:liferay:liferay_portal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140206");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-06-11 02:44:42 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-12 20:29:00 +0000 (Wed, 12 Jun 2019)");

  script_cve_id("CVE-2019-6588");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Liferay Portal < 7.1 GA4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_liferay_consolidation.nasl");
  script_mandatory_keys("liferay/portal/detected");

  script_tag(name:"summary", value:"Liferay Portal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Liferay Portal is prone to multiple vulnerabilities:

  - Velocity/FreeMarker templates do not properly restrict variable usage

  - Multiple permission vulnerabilities in 7.0 CE GA3

  - Multiple XSS vulnerabilities in 7.0 CE GA3

  - Password policy circumvention via forgot password

  - DoS vulnerability via SessionClicks

  - RCE via TunnelServlet

  - ThreadLocal may leak variables

  - Password exposure in Server Administration

  - Password exposure during a data migration

  - Open redirect vulnerability in Search

  - DoS vulnerabilities in Apache Commons FileUpload

  - XXE vulnerability in Apache Tika");

  script_tag(name:"affected", value:"Liferay Portal prior to version 7.1 GA4.");

  script_tag(name:"solution", value:"Update to version 7.1 GA4 or later.");

  script_xref(name:"URL", value:"https://portal.liferay.dev/learn/security/known-vulnerabilities/-/categories/113764476?p_r_p_categoryId=113764476");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/153252");

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

if (version_is_less(version: version, test_version: "7.1.ga4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.ga4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
