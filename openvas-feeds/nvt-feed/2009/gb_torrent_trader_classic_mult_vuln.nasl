# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:torrenttrader:torrenttrader_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800522");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:30:05 +0000 (Thu, 15 Feb 2024)");
  script_cve_id("CVE-2009-2156", "CVE-2009-2157", "CVE-2009-2158",
                "CVE-2009-2159", "CVE-2009-2160", "CVE-2009-2161");
  script_name("TorrentTrader Classic Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_torrent_trader_classic_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("torrenttraderclassic/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35456");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35369");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504294/100/0/threaded");

  script_tag(name:"affected", value:"TorrentTrader Classic version 1.09 and prior.");

  script_tag(name:"insight", value:"Multiple flaws due to: improper validation of user-supplied input data to
  different parameters and Access to the '.php' scripts are not properly restricted.");

  script_tag(name:"solution", value:"Upgrade to TorrentTrader Classic version 2.0.6 or later.");

  script_tag(name:"summary", value:"TorrentTrader Classic is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject and execute
  arbitrary SQL queries via malicious SQL code, and can gain sensitive
  information about remote system user credentials and database.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/torrenttrader");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos["version"];
dir = infos["location"];

if( dir == "/" ) dir = "";

url = dir + "/upload/browse.php?wherecatin=waraxe";

sndReq = http_get( item:url, port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( "Unknown column 'waraxe' in 'where clause'" >< rcvRes ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( ! isnull( vers ) ) {
  if( version_is_less_equal( version:vers, test_version:"1.09" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.6", install_url:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
