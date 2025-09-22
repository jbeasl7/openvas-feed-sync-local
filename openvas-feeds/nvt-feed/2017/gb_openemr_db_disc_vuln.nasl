# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112103");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-11-06 08:35:26 +0200 (Mon, 06 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-01 02:29:00 +0000 (Fri, 01 Dec 2017)");

  script_cve_id("CVE-2017-16540");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 5.0.0 Patch 5 Database Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to a database disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenEMR allows unauthenticated remote database copying because
  setup.php exposes functionality for cloning an existing OpenEMR site to an arbitrary
  attacker-controlled MySQL server via vectors involving a crafted state parameter.");

  script_tag(name:"impact", value:"A successful exploitation will allow the attackers to steal the
  contents of the backend database: social security numbers, password hashes, and any other
  sensitive data a medical records system database might hold.");

  script_tag(name:"affected", value:"OpenEMR versions before 5.0.0 Patch 5.");

  script_tag(name:"solution", value:"Update to version 5.0.0 Patch 5 or later.");

  script_xref(name:"URL", value:"http://www.open-emr.org/wiki/index.php/OpenEMR_Patches");
  script_xref(name:"URL", value:"https://isears.github.io/jekyll/update/2017/10/28/openemr-database-disclosure.html");

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

if (version_is_less(version: version, test_version: "5.0.0-5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.0-5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
