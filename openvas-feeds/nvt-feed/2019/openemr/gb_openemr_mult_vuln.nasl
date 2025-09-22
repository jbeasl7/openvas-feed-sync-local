# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142456");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-05-22 09:59:39 +0000 (Wed, 22 May 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-20 14:04:00 +0000 (Mon, 20 May 2019)");

  script_cve_id("CVE-2018-17179", "CVE-2018-17180", "CVE-2018-17181");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 5.0.1 Patch 7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenEMR is prone to multiple vulnerabilities:

  - SQL Injection in the make_task function in /interface/forms/eye_mag/php/taskman_functions.php
  via /interface/forms/eye_mag/taskman.php (CVE-2018-17179)

  - Directory Traversal exists via docid=../ to /portal/lib/download_template.php (CVE-2018-17180)

  - SQL Injection exists in the SaveAudit function in /portal/lib/paylib.php and the portalAudit
  function in /portal/lib/appsql.class.php (CVE-2018-17181)");

  script_tag(name:"affected", value:"OpenEMR prior to version 5.0.1 Patch 7.");

  script_tag(name:"solution", value:"Update to version 5.0.1 Patch 7 or later.");

  script_xref(name:"URL", value:"https://www.open-emr.org/wiki/index.php/OpenEMR_Patches");

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

if (version_is_less(version: version, test_version: "5.0.1-7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1-7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
