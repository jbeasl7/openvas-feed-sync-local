# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:brocade:netiron_os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140059");
  script_cve_id("CVE-2016-8203");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2025-09-05T15:40:40+0000");

  script_name("Brocade Security Advisory BSA-2016-168 (Memory Corruption Vulnerability)");

  script_xref(name:"URL", value:"http://www.brocade.com/en/backend-content/pdf-page.html?/content/dam/common/documents/content-types/security-bulletin/brocade-security-advisory-2016-168.pdf");

  script_tag(name:"summary", value:"A memory corruption in the IPsec code path of Brocade NetIron OS
  on Brocade MLXs 5.8.00 through 5.8.00e, 5.9.00 through 5.9.00bd, 6.0.00 and 6.0.00a images could
  allow attackers to causse a denial of service (DoS) (line card reset) via certain constructed
  IPsec control packets");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Brocade has fixed the vulnerability described in this advisory in NetIron 5.8.00ec, 5.9.00be and 6.0.00ab and later releases.");

  script_tag(name:"affected", value:"Brocade NetIron OS on Brocade MLXs 5.8.00 through 5.8.00e, 5.9.00 through 5.9.00bd, 6.0.00 and 6.0.00a images.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-14 18:46:10 +0100 (Mon, 14 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_brocade_netiron_snmp_detect.nasl");
  script_mandatory_keys("brocade_netiron/os/version", "brocade_netiron/typ");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

t = get_kb_item( "brocade_netiron/typ" );

if( "MLX" >!< t ) exit( 99 );

fix = FALSE;

if( version =~ "^5\.8\.0" )
  if( revcomp( a:version, b:"5.8.0e" ) <= 0 )  fix = '5.8.00ec';

if( version =~ "^5\.9\.0" )
  if( revcomp( a:version, b:"5.9.0bd" ) <= 0 ) fix = '5.9.00be';

if( version =~ "^6\.0\.0" )
  if( revcomp( a:version, b:"6.0.0a" ) <= 0 )  fix = '6.0.00ab';

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

