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

CPE = "cpe:/o:sophos:sfos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106903");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-06-23 10:58:06 +0700 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 16:15:00 +0000 (Tue, 20 Apr 2021)");

  script_cve_id("CVE-2011-1473", "CVE-2017-7479", "CVE-2017-12854");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sophos XG Firewall < 16.05.5 MR5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sophos_xg_consolidation.nasl");
  script_mandatory_keys("sophos/xg_firewall/detected");

  script_tag(name:"summary", value:"Sophos XG Firewall is prone multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2011-1473: [Mail Proxy] Vulnerability fix for CVE-2011-1473

  - CVE-2017-7479: [SSLVPN] OpenVPN Denial of Service due to Exhaustion of Packet-ID counter

  - CVE-2017-12854: NC-18958 [Mail Proxy] System files are accessible to authenticated non-admin
  users

  - No CVE: A path traversal vulnerability where a low privileged user may download arbitrary files
  or elevate his privileges

  Crafting a download request and adding a path traversal vector to it, an authenticated user, can
  use this function to download files that are outside the normal scope of the download feature
  (including sensitive files).

  In addition, the function can be called from a low privileged user, a user that is logged on to
  the User Portal. A combinations of these two vulnerabilities can be used to compromise the
  integrity of the server, by allowing a user to elevate his privileges.");

  script_tag(name:"affected", value:"Sophos XG Firewall prior to version 16.05.5 MR5.");

  script_tag(name:"solution", value:"Update to version 16.05.5 MR5 or later.");

  script_xref(name:"URL", value:"https://community.sophos.com/sophos-xg-firewall/b/blog/posts/sfos-16-05-5-mr5-released");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44065");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3253");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "16.05.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.05.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
