# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103260");
  script_version("2022-02-23T09:58:00+0000");
  script_tag(name:"last_modification", value:"2022-02-23 09:58:00 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-09-20 13:31:33 +0200 (Tue, 20 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-3265");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zabbix < 1.8.7 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zabbix_http_detect.nasl");
  script_mandatory_keys("zabbix/detected");

  script_tag(name:"summary", value:"Zabbix is prone to an information disclosure vulnerability
  because it fails to sufficiently validate user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to read the contents of
  arbitrary database tables. This may allow the attacker to obtain sensitive information. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"Zabbix prior to version 1.8.7.");

  script_tag(name:"solution", value:"Update to version 1.8.7 or later.");

  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-3955");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version: vers, test_version: "1.8.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.8.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
