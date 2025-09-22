# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145276");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-01-29 04:01:06 +0000 (Fri, 29 Jan 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 14:58:00 +0000 (Thu, 04 Feb 2021)");

  script_cve_id("CVE-2020-13569", "CVE-2020-19364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 6.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-site request forgery (CSRF) in the GACL functionality (CVE-2020-13569)

  - Authenticated attacker may upload and execute malicious PHP scripts through /controller.php
  (CVE-2020-19364)");

  script_tag(name:"affected", value:"OpenEMR prior to version 6.0.0.");

  script_tag(name:"solution", value:"Update to version 6.0.0 or later.");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2020-1180");
  script_xref(name:"URL", value:"https://github.com/EmreOvunc/OpenEMR_Vulnerabilities");

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

if (version_is_less(version: version, test_version: "6.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
