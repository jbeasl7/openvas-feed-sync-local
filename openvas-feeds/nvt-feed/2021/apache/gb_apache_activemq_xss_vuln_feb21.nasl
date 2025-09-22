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

CPE = "cpe:/a:apache:activemq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145347");
  script_version("2021-08-24T06:00:58+0000");
  script_tag(name:"last_modification", value:"2021-08-24 06:00:58 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-02-10 08:13:34 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_cve_id("CVE-2020-13947");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache ActiveMQ < 5.15.13, 5.16.0 < 5.16.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl");
  script_mandatory_keys("apache/activemq/detected");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An instance of an XSS vulnerability was identified to be present in the
  web based administration console on the message.jsp page of Apache ActiveMQ.");

  script_tag(name:"affected", value:"Apache ActiveMQ prior to version 5.15.13 or 5.16.1.");

  script_tag(name:"solution", value:"Upgrade to version 5.15.13, 5.16.1 or later.");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2020-13947-announcement.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.15.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.15.13");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.16.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
