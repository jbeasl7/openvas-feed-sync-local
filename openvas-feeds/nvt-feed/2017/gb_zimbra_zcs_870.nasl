# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:zimbra:collaboration";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108067");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-02-01 15:00:00 +0100 (Wed, 01 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 01:31:00 +0000 (Thu, 21 Dec 2023)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2016-3999", "CVE-2016-3401", "CVE-2016-3402", "CVE-2016-3404", "CVE-2016-3407",
                "CVE-2016-3408", "CVE-2016-3409", "CVE-2016-3410", "CVE-2016-3411", "CVE-2016-3412",
                "CVE-2016-3413", "CVE-2016-3415", "CVE-2016-5721", "CVE-2015-4852");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zimbra < 8.7.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_consolidation.nasl");
  script_mandatory_keys("zimbra/detected");

  script_tag(name:"summary", value:"Zimbra is prone to multiple security vulnerabilities because it
  fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and launch other attacks.

  Other attacks are also possible due to further, unspecific vulnerabilities.");

  script_tag(name:"affected", value:"Zimbra prior to version 8.7.0 GA.");

  script_tag(name:"solution", value:"Update to version 8.7.0 GA or later.");

  script_xref(name:"URL", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.7.0#Security_Fixes");
  script_xref(name:"URL", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"8.7.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.7.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
