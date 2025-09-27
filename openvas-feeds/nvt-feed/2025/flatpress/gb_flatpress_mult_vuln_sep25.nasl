# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125325");
  script_version("2025-09-26T15:41:32+0000");
  script_tag(name:"last_modification", value:"2025-09-26 15:41:32 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-25 15:42:12 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("FlatPress <= 1.4.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Broken Authentication: Current Password not Required When Changing Password.

  - Stored HTML Injection: Allows an attacker to inject and store arbitrary HTML in blog entries,
  which is rendered to users, enabling phishing or malicious content execution.");

  script_tag(name:"affected", value:"FlatPress version 1.4.1 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 25th September, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://msecureltd.blogspot.com/2025/09/friday-fun-pentest-series-42-current.html");
  script_xref(name:"URL", value:"https://msecureltd.blogspot.com/2025/09/friday-fun-pentest-series-41-stored.html");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2025/Sep/63");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2025/Sep/62");

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

if (version_is_less_equal(version: version, test_version: "1.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
