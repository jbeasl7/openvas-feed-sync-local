# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100632");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-10 13:21:57 +0200 (Mon, 10 May 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-1482");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple < 1.7.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");


  script_tag(name:"summary", value:"CMS Made Simple is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to steal
  cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"CMS Made Simple prior to version 1.7.1.");

  script_tag(name:"solution", value:"Update to version 1.7.1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39997");
  script_xref(name:"URL", value:"http://blog.cmsmadesimple.org/2010/05/01/announcing-cms-made-simple-1-7-1-escade/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511178");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
location = infos["location"];

if (version_is_less(version: vers, test_version: "1.7.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
