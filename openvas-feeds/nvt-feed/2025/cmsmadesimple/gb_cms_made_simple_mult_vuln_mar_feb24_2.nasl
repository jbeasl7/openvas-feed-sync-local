# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128116");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-09 12:00:00 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-26 15:38:35 +0000 (Wed, 26 Feb 2025)");

  script_cve_id("CVE-2024-1527", "CVE-2024-1528", "CVE-2024-1529");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple < 2.2.15 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-1527: Unrestricted file upload allows an authenticated user to bypass the security
  measures of the upload functionality and potentially create a remote execution of commands via
  webshell.

  - CVE-2024-1528: Not sufficient encode user-controlled input, results in a cross-site scripting
  (XSS) through /admin/moduleinterface.php, in multiple parameters. This could allow a remote
  attacker to send a specially crafted JavaScript payload to an authenticated user and partially
  hijack their browser session.

  - CVE-2024-1529: Not sufficient encode user-controlled input, results in a cross-site scripting
  (XSS) through /admin/adduser.php, in multiple parameters. This could allow a remote
  attacker to send a specially crafted JavaScript payload to an authenticated user and partially
  hijack their browser session.");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.14 and prior.");

  script_tag(name:"solution", value:"Update to version 2.2.15 or later.");

  script_xref(name:"URL", value:"https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-cms-made-simple");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/177243/CMS-Made-Simple-2.2.19-Cross-Site-Scripting.html");

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

if (version_is_less_equal(version: version, test_version: "2.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
