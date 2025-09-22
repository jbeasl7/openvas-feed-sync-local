# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901002");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2003-1574");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user login
  credentials. By entering a valid username, an arbitrary or null password, and clicking on the
  'remember me' button.");

  script_tag(name:"impact", value:"Successful exploitation could allows to bypass the
  authentication process to gain unauthorized access to the system with the privileges of the
  victim.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 1.6.1 only.");

  script_tag(name:"solution", value:"Update to version 1.7.1.1 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/40347");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14170");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=748739&group_id=64258&atid=506846");

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

if (version_is_equal(version: version, test_version: "1.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
