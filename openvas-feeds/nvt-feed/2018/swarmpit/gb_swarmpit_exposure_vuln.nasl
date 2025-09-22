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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114014");
  script_version("2021-09-29T05:25:13+0000");
  script_tag(name:"last_modification", value:"2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2018-07-23 17:04:15 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Swarmpit Web UI Public WAN (Internet) / Public LAN Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("global_settings.nasl", "gb_swarmpit_detect.nasl");
  script_mandatory_keys("swarmpit/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://info.lacework.com/hubfs/Containers%20At-Risk_%20A%20Review%20of%2021%2C000%20Cloud%20Environments.pdf");

  script_tag(name:"summary", value:"The script checks if the Swarmpit Web UI is accessible from a
  public WAN (Internet) / public LAN.");

  script_tag(name:"insight", value:"The installation or configuration of Swarmpit might be
  incomplete and therefore it is unprotected and exposed to the public.");

  script_tag(name:"vuldetect", value:"Checks if the Swarmpit UI is accessible from a public WAN
  (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"Access to the dashboard gives you top level access to all aspects
  of administration for the cluster it is assigned to manage. That includes managing applications,
  containers, starting workloads, adding and modifying applications, and setting key security
  controls.");

  script_tag(name:"solution", value:"It is highly recommended to consider the following:

  - Regardless of network policy, use MFA for all access.

  - Apply strict controls to network access, especially for UI and API ports.

  - Use SSL/TLS for all servers and use valid certificates with proper expiration and enforcement
  policies.

  - Investigate VPN (bastion), reverse proxy or direct connect connections to sensitive servers.

  - Look into product and services such as Lacework in order to discover, detect, prevent, and
  secure your container services.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("network_func.inc");
include("host_details.inc");

if(!is_public_addr())
  exit(0);

CPE = "cpe:/a:swarmpit:swarmpit";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if(get_kb_item("swarmpit/" + port + "/detected")) {
  report = "Swarmpit UI is exposed to the public under the following URL: " + http_report_vuln_url(port: port, url: "/", url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);