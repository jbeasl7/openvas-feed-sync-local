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

CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106835");
  script_version("2022-02-23T10:57:32+0000");
  script_tag(name:"last_modification", value:"2022-02-23 10:57:32 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-05-29 11:13:22 +0700 (Mon, 29 May 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-2824");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Zabbix Server Active Proxy Trapper RCE Vulnerability (CVE-2017-2824)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zabbix_http_detect.nasl");
  script_mandatory_keys("zabbix/detected");

  script_tag(name:"summary", value:"Zabbix is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"insight", value:"An exploitable code execution vulnerability exists in the
  trapper command functionality of Zabbix Server. A specially crafted set of packets can cause a
  command injection resulting in remote code execution. An attacker can make requests from an active
  Zabbix Proxy to trigger this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Zabbix version 2.4.x.");

  script_tag(name:"solution", value:"By removing the three default script entries inside of the
  Zabbix Server's 'Zabbix' database, an attacker would be unable to actually execute code, even if
  they can insert hosts with spoofed addresses into the database. This should not affect an
  organizations current operations, unless the scripts are actually used.");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0325");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\.4") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
