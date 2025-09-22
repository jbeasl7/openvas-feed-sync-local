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

CPE = "cpe:/a:netwin:surgemail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900840");
  script_version("2022-05-24T09:30:09+0000");
  script_tag(name:"last_modification", value:"2022-05-24 09:30:09 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2008-7182");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SurgeMail < 3.9g2 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_surgemail_consolidation.nasl");
  script_mandatory_keys("surgemail/detected");

  script_tag(name:"summary", value:"SurgeMail is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in the IMAP service is caused due the way it
  handles the APPEND command which can be exploited via a long first argument.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users
  to cause a denial of service and possibly execute arbitrary code in the victim's system.");

  script_tag(name:"affected", value:"SurgeMail prior to version 3.9g2.");

  script_tag(name:"solution", value:"Update to version 3.9g2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30000");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496482");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "3.9g.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9g.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
