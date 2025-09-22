# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106180");
  script_version("2022-02-23T10:57:32+0000");
  script_tag(name:"last_modification", value:"2022-02-23 10:57:32 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-08-17 11:04:27 +0700 (Wed, 17 Aug 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Zabbix Default Guest Account (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_zabbix_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("zabbix/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Zabbix has a default guest account with no password set. It was
  possible to access the dashboard without special authentication.");

  script_tag(name:"vuldetect", value:"Tries to access the dashboard via HTTP without credentials.");

  script_tag(name:"insight", value:"Initially Zabbix has a guest account with no password set but
  as well with no privileges on Zabbix objects which is used to access the user interface when no
  credentials are set.");

  script_tag(name:"impact", value:"An attacker may use this account to use further attacks to
  elevate his privileges.");

  script_tag(name:"solution", value:"Disable the guest account.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

if (http_vuln_check(port: port, url: dir + "/zabbix.php?action=dashboard.view", check_header: TRUE,
                    pattern: "<title>Dashboard</title>", extra_check: 'title="Sign out"')) {
  report = http_report_vuln_url(port: port, url: dir + "/zabbix.php?action=dashboard.view");
  security_message(port: port, data: report);
  exit(0);
}

if (http_vuln_check(port: port, url: dir + "/dashboard.php", check_header: TRUE,
                    pattern: "<title>.*Dashboard</title>", extra_check: "Connected as 'guest'")) {
  report = http_report_vuln_url(port: port, url: dir + "/dashboard.php");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
