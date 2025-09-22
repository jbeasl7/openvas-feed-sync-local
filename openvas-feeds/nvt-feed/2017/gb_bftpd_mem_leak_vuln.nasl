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

CPE = "cpe:/a:bftpd:bftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140515");
  script_version("2021-09-17T09:09:50+0000");
  script_tag(name:"last_modification", value:"2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-11-21 10:35:01 +0700 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-16892");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Bftpd < 4.7 Memory Leak Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_bftpd_detect.nasl");
  script_mandatory_keys("bftpd/detected");

  script_tag(name:"summary", value:"Bftpd is prone to a memory leak vulnerability in the file rename
  function.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Bftpd version 4.6 and prior.");

  script_tag(name:"solution", value:"Update to version 4.7 or later.");

  script_xref(name:"URL", value:"http://bftpd.sourceforge.net/news.html#032390");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);