# Copyright (C) 2016 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111088");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-02-22 08:00:00 +0100 (Mon, 22 Feb 2016)");
  script_name("Multiple DVR Devices Multiple Vulnerabilities (Feb 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.pentestpartners.com/security-blog/pwning-cctv-cameras/");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  script_tag(name:"summary", value:"Multiple Digital Video Recorder (DVR) devices are prone to
  authentication bypass and remote code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"The flaw is due to the device:

  - accepting access to the files /view2.html or /main.html if the two cookies 'dvr_usr' and
  'dvr_pwd' have any value and the cookie 'dvr_camcnt' a value of 2, 4, 8 or 24.

  - providing an unauthenticated access to a web shell

  These vulnerabilities were known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to:

  - gain access to the administration interface of the device and manipulate the device's settings

  - execute remote commands on the base system");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
buf = http_get_cache( item:"/", port:port );

if( "erver: JAWS/1.0" >< banner || '<span lxc_lang="index_Remember_me">Remember me</span></p>' >< buf || "Network video client</span>" >< buf ) {

  url = "/shell?id";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  if( "uid=0(root) gid=0(root)" >< buf ) {
    report += "Remote code execution, " + http_report_vuln_url( port:port, url:url ) + '\n';
    vuln = TRUE;
  }

  foreach file( make_list( "/view2.html", "/main.html" ) ) {

    req = http_get( item:file, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( '<span lxc_lang="view_Channel">Channel</span>' >< buf || '<a id="connectAll" lxc_lang="view_Connect_all">' >< buf ) {
      report += "Authentication bypass, " + http_report_vuln_url( port:port, url:file ) + '\n';
      vuln = TRUE;
    }
  }
}

if( vuln ) {
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
