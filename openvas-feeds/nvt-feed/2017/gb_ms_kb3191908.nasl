# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811096");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-8509");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-06-14 12:44:26 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft OneNote Remote Code Execution Vulnerability (KB3191908)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3191908");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Microsoft Office software when the Office software fails to properly handle
  objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to use a specially crafted file and perform actions in the security context of
  the current user. The file could then, for example, take actions on behalf of
  the logged-on user with the same permissions as the current user.");

  script_tag(name:"affected", value:"Microsoft OneNote 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3191908");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98812");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_mandatory_keys("MS/Office/OneNote/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

exeVer = infos["version"];
if( ! exeVer || exeVer !~ "^14\." )
  exit( 0 );

notePath = infos["location"];
if( ! notePath || "Could not find the install location" >< notePath )
  exit( 0 );

noteVer = fetch_file_version( sysPath:notePath, file_name:"onenotesyncpc.dll" );
if( ! noteVer )
  exit( 0 );

if( noteVer =~ "^14\." && version_is_less( version:noteVer, test_version:"14.0.7182.5000" ) ) {
   report = 'File checked:     ' + notePath + "\onenotesyncpc.dll"  + '\n' +
            'File version:     ' + noteVer  + '\n' +
            'Vulnerable range: ' + "14.0 - 14.0.7182.4999" + '\n' ;
   security_message( data:report );
   exit( 0 );
}

exit( 99 );
