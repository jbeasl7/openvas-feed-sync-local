# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114117");
  script_version("2021-11-23T14:13:02+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-23 14:13:02 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-31 13:28:10 +0200 (Wed, 31 Jul 2019)");
  script_cve_id("CVE-2019-3948");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_name("Amcrest Technologies IP Camera Unauthenticated Remote Audio Streaming Vulnerability");
  script_dependencies("gb_amcrest_ip_camera_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("amcrest/ip_camera/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/47188");
  script_xref(name:"URL", value:"https://sup-files.s3.us-east-2.amazonaws.com/Firmware/IP2M-841/JS+IP2M-841/Changelog/841_721_HX1_changelog_20190729.txt");

  script_tag(name:"summary", value:"The remote installation of Amcrest's IP camera software is prone
  to an unauthenticated remote audio streaming vulnerability.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker can connect to the /videotalk
  endpoint and listen to the audio that the camera is capturing.");

  script_tag(name:"vuldetect", value:"Checks if the /videotalk URL is reachable.");

  script_tag(name:"affected", value:"Amcrest IP2M-841B IP camera firmware version V2.520.AC00.18.R
  is known to be affected. Other models or versions might be affected as well.");

  script_tag(name:"solution", value:"Update to firmware version V2.420.AC00.18.R.
  Note that version 2.420 is actually later than 2.520.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:amcrest:ip_camera";

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/videotalk";

req = http_get_req(port: port, url: url, add_headers: make_array("Range", "bytes=0-\r\n"));
res = http_keepalive_send_recv(port: port, data: req, headersonly: TRUE);

# nb: All affected devices had Content-Type:Audio/DHAV but we want to make sure that we're
# also catching responses with RFC conform headers (if they ever existed).
if(res && res =~ "Content-Type\s*:\s*Audio/DHAV") {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);