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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900869");
  script_version("2022-03-01T14:58:37+0000");
  script_tag(name:"last_modification", value:"2022-03-01 14:58:37 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3274");
  script_name("Mozilla Firefox Insecure Saving Of Downloadable File - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36649");
  script_xref(name:"URL", value:"http://jbrownsec.blogspot.com/2009/09/vamos-updates.html");
  script_xref(name:"URL", value:"http://securitytube.net/Zero-Day-Demos-%28Firefox-Vulnerability-Discovered%29-video.aspx");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Local attackers may leverage this issue by replacing an arbitrary downloaded
  file by placing a file in a /tmp location before the download occurs.");
  script_tag(name:"affected", value:"Mozilla Firefox version 2.x, 3.x.");
  script_tag(name:"insight", value:"This security issue is due to the browser using a fixed path from the
  /tmp directory when a user opens a file downloaded for opening from the
  'Downloads' window. This can be exploited to trick a user into opening a file
  with potentially malicious content by placing it in the /tmp directory before
  the download takes place.");
  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is saving downloadable files insecurely.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"3.6.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.6.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
