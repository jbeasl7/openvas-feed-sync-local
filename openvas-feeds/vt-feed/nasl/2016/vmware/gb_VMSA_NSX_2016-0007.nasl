# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:nsx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105754");
  script_cve_id("CVE-2016-2079");
  script_version("2026-04-28T06:28:06+0000");
  script_name("VMware NSX product updates address a critical information disclosure vulnerability (VMSA-2016-0007)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-06-10 12:47:00 +0200 (Fri, 10 Jun 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_vmware_nsx_consolidation.nasl");
  script_mandatory_keys("vmware/nsx/detected");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0007.html");

  script_tag(name:"summary", value:"VMware NSX product updates address a critical information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/build is present on the target host.");

  script_tag(name:"insight", value:"VMware NSX with SSL-VPN enabled contain a critical input
  validation vulnerability. This issue may allow a remote attacker to gain access to sensitive
  information.");

  script_tag(name:"affected", value:"NSX 6.2 prior to 6.2.3

  NSX 6.1 prior to 6.1.7");

  script_tag(name:"solution", value:"Apply the missing update.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"6.2", test_version2:"6.2.2" ) )
  fix = "6.2.3";

else if( version_in_range( version:version, test_version:"6.1", test_version2:"6.1.6" ) )
  fix = "6.1.7";

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
