# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:comware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106619");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-02-23 16:00:27 +0700 (Thu, 23 Feb 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:22:00 +0000 (Tue, 16 Aug 2022)");

  script_cve_id("CVE-2015-1794", "CVE-2015-3193", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HPE Network Products Remote Denial of Service (DoS), Disclosure of Sensitive Information Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  # nb: Only SNMP detection included as the model / release is currently not getting extracted via
  # / from the SSH banner.
  script_dependencies("gb_hp_comware_platform_snmp_detect.nasl");
  script_mandatory_keys("hp/comware_device");

  script_tag(name:"summary", value:"Potential security vulnerabilities with OpenSSL have been addressed for HPE
Network products including Comware 5, Comware 7, IMC, and VCX.");

  script_tag(name:"vuldetect", value:"Check the release version.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05398322");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE) ) exit( 0 );
if( ! model = get_kb_item( "hp/comware_device/model" ) ) exit( 0 );
if( ! release = get_kb_item( "hp/comware_device/release" ) ) exit( 0 );

if( model =~ '^MSR20-1(0|1|2|3|5)' ) {
  report_fix = 'R2516';
  fix = '2516';
}

else if (model =~ '^MSR20-(20|21|40)') {
  report_fix = 'R2516';
  fix = '2516';
}

else if (model =~ '^MSR30-(10|11|11E|11F|16|20|40|60)') {
  report_fix = 'R2516';
  fix = '2516';
}

else if (model =~ '^MSR50-(40|60)') {
  report_fix = 'R2516';
  fix = '2516';
}

else if (model =~ '^MSR9(0|2)0') {
  report_fix = 'R2516';
  fix = '2516';
}

else if (model =~ '^MSR93(0|1|3|5|6)') {
  report_fix = 'R2516';
  fix = '2516';
}

if( model =~ '^(A|A-)?125(0|1)(0|8|4)' ) {
  if( version =~ '^7\\.' )
  {
    report_fix = 'R7377';
    fix = '7377';
  }
  else
  {
    report_fix = 'R1829P02';
    fix = '1829P02';
  }
}

else if (model =~ '^(A|A-)?105(00|08|04|12)' || model =~ 'FF 1190(0|8)') {
  if( version =~ '^7\\.' )
  {
    report_fix = 'R7180';
    fix = '7180';
  }
  else
  {
    report_fix = 'R1210P02';
    fix = '1210P02';
  }
}

else if( model =~ '^75(0|1)(0|2|3|6)' )
{
  if( version =~ '^7\\.' )
  {
    report_fix = 'R7180';
    fix = '7180';
  }
  else
  {
    report_fix = 'R6710P02';
    fix = '6710P02';
  }
}

else if( model =~ '^(A|A-)?5500-(24|48)(.*)?-4SFP HI' )
{
  report_fix = 'R5501P21';
  fix = '5501P21';
}

else if( model =~ '^WX500(2|4)' )
{
  report_fix = 'R2507P44';
  fix = '2507P44';
}

else if( model =~ '^U200-(A|S)' )
{
  report_fix = 'F5123P33';
  fix = '5123P33';
}

else if( model =~ '^59(0|2)0' )
{
  report_fix = 'R2432P01';
  fix = '2432P01';
}

else if( model =~ '^MSR100((2-4)|(3-8S))' )
{
  report_fix = 'R0306P12';
  fix = '0306P12';
}

else if( model =~ '^MSR200(3|4)' )
{
  report_fix = 'R0306P12';
  fix = '0306P12';
}

else if( model =~ '^MSR30(12|24|44|64)' )
{
  report_fix = 'R0306P12';
  fix = '0306P12';
}

else if( model =~ '^MSR40(00|60|80)' )
{
  report_fix = 'R0306P12';
  fix = '0306P12';
}

else if( model =~ '^(FF )?79(10|04)' )
{
  report_fix = 'R2150';
  fix = '2150';
}

else if( model =~ '^(A|A-)?5130-(24|48)-' )
{
  report_fix = 'R3113P02';
  fix = 'R3113P02';
}

else if( model =~ '^1950-(24G|48G)' )
{
  report_fix = 'R3113P02';
  fix = '3113P02';
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

