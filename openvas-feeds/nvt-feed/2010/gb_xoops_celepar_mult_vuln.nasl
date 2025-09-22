# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:alexandre_amaral:xoops_celepar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801153");
  script_version("2022-01-28T11:00:10+0000");
  script_tag(name:"last_modification", value:"2022-01-28 11:00:10 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4698", "CVE-2009-4713", "CVE-2009-4714");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Xoops Celepar <= 2.2.4 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xoops_celepar_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xoops_celepar/http/detected");

  script_tag(name:"summary", value:"Xoops Celepar is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The flaw exists in 'Qas (aka Quas) module'. Input passed to the 'codigo' parameter in
  modules/qas/aviso.php and modules/qas/imprimir.php, and the 'cod_categoria' parameter in
  modules/qas/categoria.php is not properly sanitised before being used in an SQL query.

  - The flaw exists in 'Qas (aka Quas) module' and 'quiz'module. Input passed to the 'opcao'
  parameter to modules/qas/index.php, and via the URL to modules/qas/categoria.php,
  modules/qas/index.php, and modules/quiz/cadastro_usuario.php is not properly sanitised before
  being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may allow an attacker to view, add,
  modify data, or delete information in the back-end database and also conduct cross-site
  scripting.");

  script_tag(name:"affected", value:"Xoops Celepar version 2.2.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35966");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9249");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9261");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51985");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

res = http_get_cache(port: port, item: dir + "/modules/qas/index.php");

if (res =~ "^HTTP/1\.[01] 200" && "_MI_QAS_POR" >< res) {
  url = dir + "/modules/qas/categoria.php?cod_categoria='><script>alert('VT-XSS-Exploit');</script>";

  if (http_vuln_check(port: port, url: url, pattern: "VT-XSS-Exploit", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

res = http_get_cache(port: port, item: dir + "/modules/quiz/login.php");

if (res =~ "^HTTP/1\.[01] 200" && "Quiz:" >< res) {
  url = dir + "/module/quiz/cadastro_usuario.php/>'><ScRiPt>alert('VT-XSS-Exploit');</ScRiPt>";

  if (http_vuln_check(port: port, url: url, pattern: "VT-XSS-Exploit", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
