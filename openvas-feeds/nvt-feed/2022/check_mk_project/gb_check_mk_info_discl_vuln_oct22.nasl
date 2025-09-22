# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkmk:checkmk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148911");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-11-15 07:38:11 +0000 (Tue, 15 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk < 2.0.0p30, 2.1.x < 2.1.0p16, 2.2.x < 2.2.0i1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_checkmk_server_http_detect.nasl");
  script_mandatory_keys("checkmk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When using the Agent updater the Checkmk server needs a secret
  in order to allow the agent to download new agents. For security reasons this secret is unique
  for each host and generated with the cmk-update-agent register command. Unfortunately the
  generated host secret was written to the cmk-update-agent.log. This logfile is not protected and
  usually world-readable.

  With this secret one can download the current agent from the Checkmk server. Included in that
  agent package are the plugin configs which can contain other secrets. (e.g. database
  credentials)");

  script_tag(name:"affected", value:"Checkmk version 2.2.x and prior.");

  script_tag(name:"solution", value:"Update to version 2.0.0p30, 2.1.0p16, 2.2.0i1 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/14919");

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

if (version_is_less(version: version, test_version: "2.0.0p30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0p30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.0p16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0i1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.0i1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
