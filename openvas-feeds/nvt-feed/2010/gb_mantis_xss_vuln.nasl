# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801449");
  script_version("2022-03-15T08:15:23+0000");
  script_tag(name:"last_modification", value:"2022-03-15 08:15:23 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-2802", "CVE-2009-2802");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-12 21:33:00 +0000 (Tue, 12 Nov 2019)");

  script_name("MantisBT < 1.2.2 Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.mantisbt.org/blog/?p=113");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/03/7");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/02/16");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=11952");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl");
  script_mandatory_keys("mantisbt/detected");

  script_tag(name:"insight", value:"The following flaws exist:

  - the application allows remote authenticated users to inject arbitrary web script or HTML via an
  HTML document with a '.gif' filename extension, related to inline attachments (CVE-2010-2802)

  - insecure handling of attachments and MIME types (CVE-2009-2802)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 1.2.2 or later.");

  script_tag(name:"summary", value:"MantisBT is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting,
  cross-domain scripting or other browser attacks.");

  script_tag(name:"affected", value:"MantisBT version prior to version 1.2.2.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
