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

CPE = "cpe:/a:w-agora:w-agora";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100869");
  script_version("2022-04-12T08:46:17+0000");
  script_tag(name:"last_modification", value:"2022-04-12 08:46:17 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2010-10-25 12:51:03 +0200 (Mon, 25 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-4867", "CVE-2010-4868");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("W-Agora 'search.php' LFi and XSS Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");

  script_family("Web application abuses");
  script_dependencies("gb_w-agora_cms_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("w-agora/http/detected");

  script_tag(name:"summary", value:"w-Agora is prone to a local file-include (LFi) vulnerability and
  a cross-site scripting (XSS) vulnerability because it fails to properly sanitize user-supplied
  input.");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability
  using directory-traversal strings to view and execute local files within the context of the
  webserver process. Information harvested may aid in further attacks.

  The attacker may leverage the cross-site scripting issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"W-Agora version 4.2.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44370");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = make_list( "/search.php", "/search.php3" );

vt_strings = get_vt_strings();

foreach file( files ) {
  url = dir + file + "?bn=%3Cbody%20onload=alert(%27" + vt_strings["lowercase"] + "%27)%3E";

  if( http_vuln_check( port:port, url:url, pattern:"<body onload=alert\('" + vt_strings["lowercase"] + "'\)>",
                       extra_check:make_list( "Could not access configuration file" ) ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );