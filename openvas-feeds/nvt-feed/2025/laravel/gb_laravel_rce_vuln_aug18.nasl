# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:laravel:laravel";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.135007");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-04-24 18:10:18 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-10 16:20:18 +0000 (Mon, 10 Jun 2024)");

  script_cve_id("CVE-2018-15133");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Laravel < 5.6.30 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_laravel_consolidation.nasl");
  script_mandatory_keys("laravel/detected");

  script_tag(name:"summary", value:"Laravel is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote command execution is possible via a correctly formatted
  HTTP X-XSRF-TOKEN header, due to an insecure unserialize call of the decrypt method in
  Illuminate/Encryption/Encrypter.php. Authentication is not required, however exploitation
  requires knowledge of the Laravel APP_KEY. Similar vulnerabilities appear to exist within Laravel
  cookie tokens based on the code fix. In some cases the APP_KEY is leaked which allows for
  discovery and exploitation.");

  script_tag(name:"affected", value:"Laravel prior to version 5.6.30.");

  script_tag(name:"solution", value:"Update to version 5.6.30 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/153641/PHP-Laravel-Framework-Token-Unserialize-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.6.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
