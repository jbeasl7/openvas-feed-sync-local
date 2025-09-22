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

CPE = "cpe:/a:vmware:vrealize_log_insight";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105752");
  script_version("2023-02-09T10:30:18+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:30:18 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2016-06-10 12:19:55 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");

  script_cve_id("CVE-2016-2081", "CVE-2016-2082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware vRealize Log Insight Multiple Vulnerabilities (VMSA-2016-0008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_vrealize_log_insight_consolidation.nasl");
  script_mandatory_keys("vmware/vrealize_log_insight/detected");

  script_tag(name:"summary", value:"VMware vRealize Log Insight is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-2081: Stored cross-site scripting (XSS)

  - CVE-2016-2082: Cross-site request forgery (CSRF)");

  script_tag(name:"affected", value:"VMware vRealize Log Insight prior to version 3.3.2.");

  script_tag(name:"solution", value:"Update to version 3.3.2 or later.");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2016-0008.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"3.3.2" ) )
  fix = "3.3.2 Build 3951163";

if( version == "3.3.2" ) {
  build = get_kb_item("vmware/vrealize_log_insight/build");
  if( build && int( build ) > 0 )
    if( int( build ) < int( 3951163 ) )
      fix = "3.3.2 Build 3951163";
}

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
