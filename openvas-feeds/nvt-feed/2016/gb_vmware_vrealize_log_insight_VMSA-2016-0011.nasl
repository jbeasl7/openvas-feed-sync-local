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
  script_oid("1.3.6.1.4.1.25623.1.0.105870");
  script_version("2023-02-09T10:30:18+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:30:18 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2016-08-15 14:43:37 +0200 (Mon, 15 Aug 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-5332");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware vRealize Log Insight Directory Traversal Vulnerability (VMSA-2016-0011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_vrealize_log_insight_consolidation.nasl");
  script_mandatory_keys("vmware/vrealize_log_insight/detected");

  script_tag(name:"summary", value:"VMware vRealize Log Insight is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"VMware vRealize Log Insight contains a vulnerability that may
  allow for a directory traversal attack. Exploitation of this issue may lead to a partial
  information disclosure.");

  script_tag(name:"affected", value:"VMware vRealize Log Insight prior to version 3.6.0.");

  script_tag(name:"solution", value:"Update to version 3.6.0 or later.");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2016-0011.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"3.6.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
