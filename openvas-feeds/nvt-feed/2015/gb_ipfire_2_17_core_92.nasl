# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105321");
  script_version("2025-07-17T05:43:33+0000");
  script_cve_id("CVE-2015-1793", "CVE-2015-5400");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 21:30:00 +0000 (Fri, 30 Nov 2018)");
  script_tag(name:"creation_date", value:"2015-08-18 13:35:54 +0200 (Tue, 18 Aug 2015)");
  script_name("IPFire < 2.17 - Core Update 92 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ipfire/system-release");

  script_xref(name:"URL", value:"https://www.ipfire.org/blog/ipfire-2-17-core-update-92-released");

  script_tag(name:"summary", value:"IPFire is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities are fixed with IPFire 2.17 - Core
  Update 92:

  - openssl 1.0.2d: The openssl package has been updated to version 1.0.2d because of a high
  severity security fix filed under CVE-2015-1793.

  - Squid Advisory SQUID-2015:2: This update comes with a patched version of squid to fix
  SQUID-2015:2.");

  script_tag(name:"affected", value:"IPFire versions prior to 2.17 - Core Update 92.");

  script_tag(name:"solution", value:"Update to version 2.17 - Core Update 92 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if( ! rls = get_kb_item( "ipfire/system-release" ) )
  exit( 0 );

if( "IPFire" >!< rls )
  exit( 0 );

vers = eregmatch( pattern:'IPFire ([0-9.]+[^ ]*)', string:rls );
if( ! isnull( vers[1] ) )
  version = vers[1];

if( ! version )
  exit( 0 );

c = eregmatch( pattern:"core([0-9]+)", string:rls );
if( ! isnull( c[1] ) )
  core = c[1];
else
  core = 0;

chk_version = version + "." + core;

if( version_is_less( version:chk_version, test_version:"2.17.92" ) ) {
  report = report_fixed_ver( installed_version:version + " - Core Update" + core, fixed_version:"2.17 - Core Update 92" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
