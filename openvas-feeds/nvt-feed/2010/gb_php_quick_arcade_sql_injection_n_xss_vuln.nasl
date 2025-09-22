# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801364");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1661", "CVE-2010-1662");
  script_name("PHP Quick Arcade <= 3.0.21 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_quick_arcade_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-quick-arcade/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12416/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39733");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1013");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1004-exploits/phpquickarcade-sqlxss.txt");

  script_tag(name:"summary", value:"PHP Quick Arcade is prone to SQL injection (SQLi) and cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Input validation errors in the 'Arcade.php' and 'acpmoderate.php' scripts when processing the
  'phpqa_user_c' cookie or the 'id' parameter, which could be exploited by malicious people to
  conduct SQL injection attacks.

  - Input validation error in the 'acpmoderate.php' script when processing the 'serv' parameter,
  which could allow cross site scripting attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify data.");

  script_tag(name:"affected", value:"PHP-Quick-Arcade version 3.0.21 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

vers = get_kb_item("www/" + port + "/PHP-Quick-Arcade");
if(!vers)
  exit(0);

vers = eregmatch(pattern:"^(.+) under (/.*)$", string:vers);
if(isnull(vers[1]))
  exit(0);

if(version_is_less_equal(version:vers[1], test_version:"3.0.21")) {
  report = report_fixed_ver(installed_version:vers[1], fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
