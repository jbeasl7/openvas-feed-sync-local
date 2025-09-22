# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:eggheads:eggdrop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100228");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-08 19:01:22 +0200 (Wed, 08 Jul 2009)");
  script_cve_id("CVE-2007-2807");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eggdrop < 1.6.19 Server Module Message Handling Remote Buffer Overflow Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("eggdrop_detect.nasl");
  script_mandatory_keys("eggdrop/installed");

  script_tag(name:"summary", value:"Eggdrop Server Module is prone to a remote buffer-overflow
  vulnerability because the application fails to bounds-check user-supplied data before copying it
  into an insufficiently sized buffer.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"Eggdrop 1.6.18 is known to be vulnerable. Other versions may be
  affected as well.");

  script_tag(name:"solution", value:"Update to version 1.6.19 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24070");
  script_xref(name:"URL", value:"https://github.com/eggheads/eggdrop/blob/v1.6.19/doc/UPDATES1.6#L41");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.6.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.19");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);