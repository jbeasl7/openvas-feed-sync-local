# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103113");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-1092");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.6 Remote Integer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to an integer overflow vulnerability because it
  fails to ensure that integer values are not overrun.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits of this vulnerability allow remote
  attackers to execute arbitrary code in the context of a webserver affected by the issue. Failed
  attempts will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.6.");

  script_tag(name:"solution", value:"Update to version 5.3.6 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20110611011255/http://www.securityfocus.com/bid/46786");
  script_xref(name:"URL", value:"http://comments.gmane.org/gmane.comp.security.oss.general/4436");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc/?view=revision&revision=309018");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
