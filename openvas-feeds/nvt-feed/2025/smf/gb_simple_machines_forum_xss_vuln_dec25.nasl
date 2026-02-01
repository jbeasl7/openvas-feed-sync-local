# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128193");
  script_version("2026-01-13T05:47:36+0000");
  script_tag(name:"last_modification", value:"2026-01-13 05:47:36 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"creation_date", value:"2025-12-23 10:00:20 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-67163");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Simple Machines Forum (SMF) <= 2.1.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machines Forum (SMF) is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value: "A stored cross-site scripting (XSS) vulnerability in Simple
  Machines Forum v2.1.6 allows attackers to execute arbitrary web scripts or HTML via injecting a
  crafted payload into the Forum Name parameter.");

  script_tag(name:"affected", value:"SMF versions 2.1.6 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 23rd December, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/SimpleMachines/SMF");
  script_xref(name:"URL", value:"https://github.com/SimpleMachines/SMF/blob/release-3.0/Themes/default/Stats.template.php#L26");
  script_xref(name:"URL", value:"https://github.com/SimpleMachines/SMF/security/advisories/GHSA-p2xm-x9fp-5r7x");
  script_xref(name:"URL", value:"https://github.com/mbiesiad/vulnerability-research/tree/main/CVE-2025-67163");
  script_xref(name:"URL", value:"https://wiki.simplemachines.org/smf/Installing");

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

if (version_is_less_equal(version: version, test_version: "2.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
