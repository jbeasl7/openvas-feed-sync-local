# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lucee:lucee_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146115");
  script_version("2024-03-07T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-03-07 05:06:18 +0000 (Thu, 07 Mar 2024)");
  script_tag(name:"creation_date", value:"2021-06-11 09:21:00 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-22 16:32:00 +0000 (Mon, 22 Feb 2021)");

  script_cve_id("CVE-2021-21307");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lucee < 5.3.5.96, 5.3.6.x < 5.3.6.68, 5.3.7.x < 5.3.7.47 RCE Vulnerability (GHSA-2xvv-723c-8p7r) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lucee_consolidation.nasl");
  script_mandatory_keys("lucee/detected");

  script_tag(name:"summary", value:"Lucee is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Lucee Admin there is an unauthenticated RCE vulnerability.

  Note: If access to the Lucee Administrator is blocked the vulnerability is not exploitable.");

  script_tag(name:"affected", value:"Lucee version 5.3.5.96 and prior, 5.3.6.x through 5.3.6.67 and
  5.3.7.x through 5.3.7.46.");

  script_tag(name:"solution", value:"Update to version 5.3.5.96, 5.3.6.68, 5.3.7.47 or later.");

  script_xref(name:"URL", value:"https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r");
  script_xref(name:"URL", value:"https://github.com/httpvoid/writeups/blob/main/Apple-RCE.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.3.5.96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.5.96", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.6", test_version2: "5.3.6.67")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.6.68", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.7", test_version2: "5.3.7.46")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.7.47", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
