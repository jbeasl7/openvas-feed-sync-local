# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:screenos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105406");
  script_cve_id("CVE-2015-7750");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Network based denial of service vulnerability in ScreenOS");

  script_xref(name:"URL", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10704&actp=RSS");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue is being tracked as PR 1086779 and is visible on the Customer Support website.");

  script_tag(name:"solution", value:"This issue has been resolved in ScreenOS 6.3.0r13-dnd1, 6.3.0r18-dnc1 and 6.3.0r20.");

  script_tag(name:"summary", value:"A vulnerability in ScreenOS L2TP packet processing may allow a remote network based attacker to cause a denial of service condition on ScreenOS devices by sending a crafted L2TP packet.");
  script_tag(name:"affected", value:"This issue can affect any Netscreen and ScreenOS Series products running ScreenOS.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-16 12:12:00 +0200 (Fri, 16 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_screenos_version.nasl");
  script_mandatory_keys("ScreenOS/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

display_version = version;

if( "-dnd1" >< version )
  display_fix = '6.3.0r13-dnd1';
else if( "-dnc1" >< version )
  display_fix = "6.3.0r18-dnc1";
else
  display_fix = "6.3.0r20";

fix = str_replace( string:display_fix, find:"r", replace:"." );
fix = str_replace( string:fix, find:"-", replace:"." );

version = str_replace( string:version, find:"r", replace:"." );
version = str_replace( string:version, find:"-", replace:"." );

if( version_is_less( version:version, test_version:fix ) )
{
  report = 'Installed version: ' + display_version + '\n' +
           'Fixed version:     ' + display_fix + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

