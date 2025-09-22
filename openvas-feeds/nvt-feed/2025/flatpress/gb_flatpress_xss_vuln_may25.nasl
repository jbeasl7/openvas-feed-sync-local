# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128139");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-27 09:02:25 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");

  script_cve_id("CVE-2025-44108");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FlatPress <= 1.3.1 XSS Vulnerability (CVE-2025-44108)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored Cross-Site Scripting (XSS) vulnerability exists in the
  administration panel of Flatpress CMS via the gallery captions component. An attacker with admin
  privileges can inject a malicious JavaScript payload into the system, which is then stored
  persistently.");

  script_tag(name:"affected", value:"FlatPress version 1.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.4 or later.");

  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/commit/24a6feacf1747ec19725b52c097715c8ab9c4559");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/releases/tag/1.3.1");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/releases/tag/1.4.rc2");

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

if (version_is_less_equal(version: version, test_version: "1.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
