# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phppgadmin:phppgadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151047");
  script_version("2024-06-25T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-06-25 05:05:27 +0000 (Tue, 25 Jun 2024)");
  script_tag(name:"creation_date", value:"2023-09-27 03:57:02 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-21 18:20:00 +0000 (Thu, 21 Sep 2023)");

  script_cve_id("CVE-2023-40619");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpPgAdmin < 7.14.6 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phppgadmin_http_detect.nasl");
  script_mandatory_keys("phppgadmin/detected");

  script_tag(name:"summary", value:"phpPgAdmin is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpPgAdmin is vulnerable to deserialization of untrusted data
  which may lead to remote code execution because user-controlled data is directly passed to the
  PHP 'unserialize()' function in multiple places. An example is the functionality to manage tables
  in 'tables.php' where the 'ma[]' POST parameter is deserialized.");

  script_tag(name:"affected", value:"phpPgAdmin prior to version 7.14.6.");

  script_tag(name:"solution", value:"Update to version 7.14.6 or later.");

  script_xref(name:"URL", value:"https://github.com/dub-flow/vulnerability-research/tree/main/CVE-2023-40619");
  script_xref(name:"URL", value:"https://github.com/hestiacp/phppgadmin/releases/tag/v7.14.6");

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

if (version_is_less(version: version, test_version: "7.14.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.14.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
