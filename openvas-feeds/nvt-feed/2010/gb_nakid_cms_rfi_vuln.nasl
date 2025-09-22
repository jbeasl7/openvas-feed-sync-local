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

CPE = "cpe:/a:jeffkilroy:nakid_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902082");
  script_version("2022-03-09T08:17:31+0000");
  script_tag(name:"last_modification", value:"2022-03-09 08:17:31 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-2358");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Nakid CMS <= 0.5.2 RFI Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nakid_cms_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nakidcms/http/detected");

  script_tag(name:"summary", value:"Nakid CMS is prone to a remote file inclusion (RFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the
  '/modules/catalog/upload_photo.php' script when processing the 'core[system_path]' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to include
  malicious PHP scripts and execute arbitrary commands with the privileges of the web server.");

  script_tag(name:"affected", value:"Nakid CMS version 0.5.2 and 0.5.1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13889/");

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

url = dir + "/modules/catalog/upload_photo.php?core[system_path]=VT_RFI.php";

if (http_vuln_check(port: port, url: url, pattern: "failed to open stream", extra_check: "VT_RFI.php")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
