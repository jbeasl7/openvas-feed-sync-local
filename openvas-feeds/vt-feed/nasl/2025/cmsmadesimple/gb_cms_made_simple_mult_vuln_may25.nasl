# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128161");
  script_version("2026-03-18T05:59:10+0000");
  script_tag(name:"last_modification", value:"2026-03-18 05:59:10 +0000 (Wed, 18 Mar 2026)");
  script_tag(name:"creation_date", value:"2025-06-23 12:25:34 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-03 12:57:15 +0000 (Tue, 03 Jun 2025)");

  script_cve_id("CVE-2025-5153", "CVE-2026-4225");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("CMS Made Simple <= 2.2.21 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple cross-site scripting
  (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-5153: XSS due to inadequate sanitization of user input in the 'Templates Description'
  field in the Design Manager module of the admin panel

  - CVE-2026-4225: XSS in the file admin/listusers.php of the User Management Module. Performing a
  manipulation of the argument Message results in XSS");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.21 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 17th March, 2026.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/feixuezhi/CMSMadeSimple2");
  script_xref(name:"URL", value:"https://github.com/feixuezhi/cms/wiki");
  script_xref(name:"URL", value:"https://vuldb.com/?id.351148");

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

if (version_is_less_equal(version: version, test_version: "2.2.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
