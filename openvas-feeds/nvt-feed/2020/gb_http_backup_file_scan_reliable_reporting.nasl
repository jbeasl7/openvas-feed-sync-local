# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108976");
  script_version("2022-09-13T10:15:09+0000");
  script_tag(name:"last_modification", value:"2022-09-13 10:15:09 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2020-10-26 12:13:27 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Backup File Scanner (HTTP) - Reliable Detection Reporting");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_http_backup_file_scan.nasl");
  script_mandatory_keys("http_backup_file_scan/started");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs to
  # choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd database.

  script_tag(name:"summary", value:"The script reports backup files left on the web server.");

  script_tag(name:"insight", value:"Notes:

  - 'Reliable Detection' means that a file was detected based on a strict (regex) and reliable
  pattern matching the response of the remote web server when a file was requested.

  - As the VT 'Backup File Scanner (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.140853) might run into a
  timeout the actual reporting of this vulnerability takes place in this VT instead.");

  script_tag(name:"vuldetect", value:"Reports previous enumerated backup files accessible on the
  remote web server.");

  script_tag(name:"impact", value:"Based on the information provided in these files an attacker might
  be able to gather sensitive information stored in these files.");

  script_tag(name:"solution", value:"Delete the backup files.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/10/31/1");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);
host = http_host_name(dont_add_port: TRUE);

findings = get_kb_list("www/" + host + "/" + port + "/content/backup_file_reliable");
if (findings) {

  report = 'The following backup files were identified (<URL>:<Matching pattern>):\n';

  # Sort to not report changes on delta reports if just the order is different
  findings = sort(findings);

  foreach finding(findings) {
    url_pattern = split(finding, sep: "#-----#", keep: FALSE);
    if (!url_pattern || max_index(url_pattern) != 2)
      continue;

    url = url_pattern[0];
    pattern = url_pattern[1];

    report += '\n' + url + ":" + pattern;
    vuln = TRUE;
  }
}

if (vuln) {
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
