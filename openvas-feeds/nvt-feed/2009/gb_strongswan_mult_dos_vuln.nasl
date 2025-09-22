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

CPE = "cpe:/a:strongswan:strongswan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800632");
  script_version("2021-10-21T06:59:14+0000");
  script_tag(name:"last_modification", value:"2021-10-21 06:59:14 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-1957", "CVE-2009-1958");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_name("strongSwan IKE_SA_INIT and IKE_AUTH DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An error in charon/sa/ike_sa.c charon daemon which results in NULL pointer dereference and
  crash via an invalid 'IKE_SA_INIT' request that triggers 'an incomplete state, ' followed by a
  'CREATE_CHILD_SA' request.

  - An error in incharon/sa/tasks/child_create.c charon daemon, it switches the NULL checks for TSi
  and TSr payloads, via an 'IKE_AUTH' request without a 'TSi' or 'TSr' traffic selector.");

  script_tag(name:"impact", value:"Successful exploit allows attackers to run arbitrary code,
  corrupt memory, and can cause a denial of service.");

  script_tag(name:"affected", value:"strongSwan versions prior to 4.2.15 and 4.3.x prior to 4.3.1");

  script_tag(name:"solution", value:"Update to version 4.3.1, 4.2.15 or later.");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1476");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/06/06/9");
  script_xref(name:"URL", value:"https://lists.strongswan.org/pipermail/users/2009-May/003457.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.15", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);