# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:comware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106609");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-02-20 11:04:54 +0700 (Mon, 20 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-21 02:29:00 +0000 (Tue, 21 Nov 2017)");

  script_cve_id("CVE-2015-3197", "CVE-2016-0701");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HPE Network Products Remote Unauthorized Disclosure of Information Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  # nb: Only SNMP detection included as the model / release is currently not getting extracted via
  # / from the SSH banner.
  script_dependencies("gb_hp_comware_platform_snmp_detect.nasl");
  script_mandatory_keys("hp/comware_device");

  script_tag(name:"summary", value:"Potential security vulnerabilities with OpenSSL have been addressed in HPE
Network Products including Comware v7 and VCX.");

  script_tag(name:"vuldetect", value:"Check the release version.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05390893");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE) ) exit( 0 );
if( ! model = get_kb_item( "hp/comware_device/model" ) ) exit( 0 );
if( ! release = get_kb_item( "hp/comware_device/release" ) ) exit( 0 );

if( model =~ '^(A|A-)?125(0|1)(0|8|4)' ) {
  report_fix = 'R7377P01';
  fix = '7377P01';
}

else if (model =~ '^(A|A-)?105(00|08|04|12)' || model =~ 'FF 1190(0|8)') {
  report_fix = 'R7183';
  fix = '7183';
}

else if( model =~ '^129(0|1)[0-8]' )
{
  report_fix = 'R1150';
  fix = '1150';
}

else if( model =~ '^59(0|2)0' )
{
  report_fix = 'R2432P01';
  fix = '2432P01';
}

else if( model =~ '^MSR100(2|3)-(4|8)' )
{
  report_fix = 'R0306P30';
  fix = '0306P30';
}

else if( model =~ '^MSR200(3|4)' )
{
  report_fix = 'R0306P30';
  fix = '0306P30';
}

else if( model =~ 'MSR30(12|64|44|24)' )
{
  report_fix = 'R0306P30';
  fix = '0306P30';
}

else if( model =~ '^MSR40(0|6|8)0' )
{
  report_fix = 'R0306P30';
  fix = '0306P30';
}

else if( model =~ '^MSR954' )
{
  report_fix = 'R0306P30';
  fix = '0306P30';
}

else if( model =~ '^(FF )?79(04|10)' )
{
  report_fix = 'R2150';
  fix = '2150';
}

else if( model =~ '^(A|A-)?5130-(24|48)-' )
{
  report_fix = 'R3113P02';
  fix = '3113P02';
}

else if( model =~ '^(A|A-)?5700-(48|40|32)' )
{
  report_fix = 'R2432P01';
  fix = '2432P01';
}

else if( model =~ '^FF 5930' )
{
  report_fix = 'R2432P01';
  fix = '2432P01';
}

if( model =~ '^1950-(24|48)G' )
{
  report_fix = 'R3113P02';
  fix = '3113P02';
}

else if( model =~ '^75(0|1)(0|2|3|6)' )
{
  report_fix = 'R7183';
  fix = '7183';
}

if( ! fix ) exit( 0 );

release = ereg_replace( pattern:'^R', string:release, replace:'' );

if( revcomp( a:release, b:fix ) < 0 )
{
  report = report_fixed_ver( installed_version:"R" + release, fixed_version:report_fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );




