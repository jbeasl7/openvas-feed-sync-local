# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812228");
  script_version("2021-10-18T13:34:19+0000");
  script_cve_id("CVE-2017-16953");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-18 13:34:19 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-28 02:29:00 +0000 (Thu, 28 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-11-28 18:25:42 +0530 (Tue, 28 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ZTE ZXDSL 831CII Access Bypass Vulnerability");

  script_tag(name:"summary", value:"ZTE ZXDSL 831CII devices are prone to an access bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checks whether it is
  possible to obtain sensitive information.");

  script_tag(name:"insight", value:"The flaw is due to an improper access restriction on CGI files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to modify
  router PPPoE configurations, setup malicious configurations which later could lead to disrupt
  network & its activities.");

  script_tag(name:"affected", value:"ZTE ZXDSL 831CII devices.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43188");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "gb_zte_zxdsl_831cii_telnet_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

if(!get_kb_item("zte/zxdsl_831cii/telnet/detected")) {
  banner = http_get_remote_headers(port:port);
  if(!banner || 'WWW-Authenticate: Basic realm="DSL Router"' >!< banner)
    exit(0);
}

url = "/connoppp.cgi";

if(http_vuln_check(port:port, url:url, check_header:TRUE, usecache:TRUE,
                   pattern:"Your DSL router is.*",
                   extra_check:"Configure it from the.*vpivci.cgi'>Quick.*Setup<")) {
  if(http_vuln_check(port:port, url:"/vpivci.cgi" , check_header:TRUE,
                     pattern:"Please enter VPI and VCI numbers for the Internet connection which is provided",
                     extra_check:make_list("configure your DSL Router", "VPI:", "VCI:"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);