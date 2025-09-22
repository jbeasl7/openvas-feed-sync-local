# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105322");
  script_version("2025-07-17T05:43:33+0000");
  script_cve_id("CVE-2015-5073");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 01:29:00 +0000 (Fri, 18 May 2018)");
  script_tag(name:"creation_date", value:"2015-08-18 13:36:54 +0200 (Tue, 18 Aug 2015)");
  script_name("IPFire < 2.17 - Core Update 93 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ipfire/system-release");

  script_xref(name:"URL", value:"https://www.ipfire.org/blog/ipfire-2-17-core-update-93-released");

  script_tag(name:"summary", value:"IPFire is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IPFire 2.17 - Core 93 comes with various security fixes in the
  Squid web proxy, the dnsmasq DNS proxy server and the Perl-compatible regular expressions
  library.");

  script_tag(name:"affected", value:"IPFire versions prior to 2.17 - Core Update 93.");

  script_tag(name:"solution", value:"Update to version 2.17 - Core Update 93 or later.");

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

if( version_is_less( version:chk_version, test_version:"2.17.93" ) ) {
  report = report_fixed_ver( installed_version:version + " - Core Update" + core, fixed_version:"2.17 - Core Update 93" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
