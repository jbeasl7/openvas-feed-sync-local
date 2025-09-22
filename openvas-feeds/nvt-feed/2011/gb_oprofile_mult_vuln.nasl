# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:maynard_johnson:oprofile";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802108");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_cve_id("CVE-2011-1760", "CVE-2011-2471", "CVE-2011-2472", "CVE-2011-2473");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("OProfile <= 0.9.6 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_oprofile_detect.nasl");
  script_mandatory_keys("oprofile/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=700883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47652");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/05/10/7");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/05/03/1");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=624212#19");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499232");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499233");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499234");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499235");

  script_tag(name:"summary", value:"OProfile is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to an error,

  - while handling content of event argument, provided to oprofile profiling control utility
  (opcontrol).

  - while handling 'do_dump_data' function, allows local users to create or overwrite arbitrary
  files via a crafted --session-dir argument in conjunction with a symlink attack on the opd_pipe
  file.

  - in 'utils/opcontrol', allow local users to conduct eval injection attacks and gain privileges
  via shell meta characters in the several arguments.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to run arbitrary
  commands with super-user privileges.");

  script_tag(name:"affected", value:"OProfile version 0.9.6 and prior.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

location = infos["location"];
version = infos["version"];

if( version_is_less_equal( version:version, test_version:"0.9.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See references", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
