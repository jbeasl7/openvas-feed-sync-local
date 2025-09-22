# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171310");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-19 12:46:01 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2024-51506", "CVE-2024-51507", "CVE-2024-51508", "CVE-2024-51509");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Tiki Wiki CMS Groupware <= 27.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-51506: Users who have certain permissions are able to insert a 'Create a Wiki Pages'
  stored XSS payload in the description.

  - CVE-2024-51507: Users who have certain permissions are able to insert a 'Create/Edit External
  Wiki' stored XSS payload in the Name.

  - CVE-2024-51508: Users who have certain permissions are able to insert a 'Create/Edit External
  Wiki' stored XSS payload in the Index.

  - CVE-2024-51509: Users who have certain permissions are able to insert a 'Modules'
  (aka tiki-admin_modules.php) stored XSS payload in the Name.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 27.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 19th March, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/r0ck3t1973/xss_payload/issues/8");
  script_xref(name:"URL", value:"https://github.com/r0ck3t1973/xss_payload/issues/9");
  script_xref(name:"URL", value:"https://github.com/r0ck3t1973/xss_payload/issues/10");

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

if (version_is_less_equal(version: version, test_version: "27.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
