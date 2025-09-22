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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807397");
  script_version("2022-02-15T10:35:00+0000");
  script_tag(name:"last_modification", value:"2022-02-15 10:35:00 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-02-14 12:24:12 +0530 (Tue, 14 Feb 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HP Printer Wi-Fi Direct Improper Access Control Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple HP printers are prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"HP printers with Wi-Fi Direct support let you print from a
  mobile device directly to the printer without connecting to a wireless network. Several of these
  printers are prone to a security vulnerability that allows an external system to obtain
  unrestricted remote read/write access to the printer configuration using the embedded web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an unauthenticated user to
  access certain files on the target system that are not intended to be accessible.");

  script_tag(name:"affected", value:"HP OfficeJet Pro 8710 firmware version WBP2CN1619BR

  HP OfficeJet Pro 8620 firmware version FDP1CN1547AR");

  script_tag(name:"solution", value:"Apply the following mitigation actions:

  - Disable Wi-Fi Direct functionality to protect your device

  - Enable Password Settings on the Embedded Web Server");

  script_xref(name:"URL", value:"http://neseso.com/advisories/NESESO-2017-0111.pdf");
  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2017020027");
  script_xref(name:"URL", value:"http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04577030");
  script_xref(name:"URL", value:"http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04090221");
  script_xref(name:"URL", value:"http://007software.net/hp-printers-wi-fi-direct-improper-access-control");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

cpe_list = make_list("cpe:/o:hp:officejet_pro_8620_firmware",
                     "cpe:/o:hp:officejet_pro_8710_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

url = "/DevMgmt/Email/Contacts";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "<emaildyn:EmailContacts xmlns:dd=",
                    extra_check: make_list("www\.hp\.com", "xmlns:emaildyn=", "emailservicedyn", "dictionaries"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
