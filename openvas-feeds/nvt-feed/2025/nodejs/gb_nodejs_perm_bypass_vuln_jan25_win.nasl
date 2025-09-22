# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153854");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-01-23 03:37:36 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-23083");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 20.x < 20.18.2, 21.x < 22.13.1, 23.x < 23.6.1 Worker Permission Bypass Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to a worker permission bypass
  vulnerability via InternalWorker leak in diagnostics.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"With the aid of the diagnostics_channel utility, an event can
  be hooked into whenever a worker thread is created. This is not limited only to workers but also
  exposes internal workers, where an instance of them can be fetched, and its constructor can be
  grabbed and reinstated for malicious usage.");

  script_tag(name:"affected", value:"Node.js version 20.x through 23.x.");

  script_tag(name:"solution", value:"Update to version 20.18.2, 22.13.1, 23.6.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/january-2025-security-releases");
  script_xref(name:"URL", value:"https://hackerone.com/reports/2575105");

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

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.18.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.18.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "22.13.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.13.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "22.13.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.13.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
