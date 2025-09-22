# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.813880");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2017-12575");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 18:15:00 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2018-09-07 18:21:50 +0530 (Fri, 07 Sep 2018)");

  script_name("NEC Aterm WG2600HP2 Incorrect Access Control Vulnerability");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Aug/26");

  script_tag(name:"summary", value:"NEC Aterm WG2600HP2 wireless LAN router is prone to an incorrect access control vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks
  whether it is able to access sensitive information or not.");

  script_tag(name:"insight", value:"The flaw exists due to an incorrect access control for some web service APIs.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to access configurations. This may aid to launch further attacks.");

  script_tag(name:"affected", value:"NEC Aterm WG2600HP2 wireless LAN router");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

necport = http_get_port(default:80);

buf = http_get_cache(item:"/aterm_httpif.cgi", port:necport);

if(buf =~ "Copyright.*NEC Platforms" && buf =~ "<title>.*Aterm</title>" &&
   "Server: Aterm(HT)" >< buf)
{
  data = "REQ_ID=SUPPORT_IF_GET";
  url = "/aterm_httpif.cgi/negotiate";

  req = http_post_put_req(port:necport, url:url, data:data, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
  buf = http_keepalive_send_recv(port:necport, data:req);

  if(buf =~ "^HTTP/1\.[01] 200" && "DEVICE_TYPE=" >< buf && "SUPPORT_REQ=" >< buf &&
   "Server: Aterm(HT)" >< buf && "GET_INTERFACE=" >< buf && "SET_INTERFACE=" >< buf)
  {
    report = http_report_vuln_url(port:necport, url:url);
    security_message(port:necport, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
