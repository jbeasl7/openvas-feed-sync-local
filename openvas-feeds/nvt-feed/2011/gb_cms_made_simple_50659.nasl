# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103332");
  script_version("2023-10-24T05:06:28+0000");
  script_tag(name:"last_modification", value:"2023-10-24 05:06:28 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-11-15 11:29:14 +0100 (Tue, 15 Nov 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple < 1.9.4.3 Remote Database Corruption Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to a vulnerability that could result in
  the corruption of the database.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to corrupt the database.");

  script_tag(name:"affected", value:"CMS Made Simple prior to version 1.9.4.3.");

  script_tag(name:"solution", value:"Update to version 1.9.4.3 or later.");

  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50659");

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

if (version_is_less(version: vers, test_version: "1.9.4.3")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.9.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
