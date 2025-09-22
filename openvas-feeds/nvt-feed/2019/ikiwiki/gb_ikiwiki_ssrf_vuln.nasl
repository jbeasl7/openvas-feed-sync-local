# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ikiwiki:ikiwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141529");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-06-25 06:21:14 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-17 20:15:00 +0000 (Wed, 17 Jul 2019)");

  script_cve_id("CVE-2019-9187");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ikiwiki < 3.20170111.1, 3.2018x < 3.20190228 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ikiwiki_consolidation.nasl");
  script_mandatory_keys("ikiwiki/detected");

  script_tag(name:"summary", value:"ikiwiki is prone to a server-side request forgery (SSRF)
  vulnerability via the aggregate plugin.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ikiwiki prior to version 3.20170111.1, 3.2018x and 3.2019x
  prior to version 3.20190228.");

  script_tag(name:"solution", value:"Update to version 3.20170111.1, 3.20190228 or later.");

  script_xref(name:"URL", value:"https://ikiwiki.info/news/version_3.20190228/");

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

if (version_is_less(version: version, test_version: "3.20170111.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.20170111.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_greater_equal(version: version, test_version: "3.2018") &&
    version_is_less(version: version, test_version: "3.20190228")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.20190228", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
