# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812097");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8700");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-17 12:17:13 +0530 (Fri, 17 Nov 2017)");
  script_name("Microsoft ASP.NET Core Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101712");
  script_xref(name:"URL", value:"https://github.com/aspnet/announcements/issues/279");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (CVE-2017-8700).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error
  where Cross-Origin Resource Sharing (CORS) can be bypassed.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft ASP.NET Core 1.0 and ASP.NET Core 1.1 using 'Microsoft.AspNetCore.Mvc.Core' package or 'Microsoft.AspNetCore.Mvc.Cors' package versions 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.1.0, 1.1.1, 1.1.2, 1.1.3 and 1.1.4.");

  script_tag(name:"solution", value:"Upgrade to Microsoft ASP.NET Core 2.0 or higher.
  For Microsoft ASP.NET Core 1.x upgrade 'Microsoft.AspNetCore.Mvc.Core' and
  'Microsoft.AspNetCore.Mvc.Cors' packages to version 1.0.6 or 1.1.5 or later.
  Please see the references for more info.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("misc_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# TODO: Limit to a possible known common path
fileList1 = wmi_file_fileversion( handle:handle, fileName:"Microsoft.AspNetCore.Mvc.Core", fileExtn:"dll", includeHeader:FALSE );
fileList2 = wmi_file_fileversion( handle:handle, fileName:"Microsoft.AspNetCore.Mvc.Cors", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList1 && ! fileList2 ) {
  exit( 0 );
}

report = "";

if( fileList1 && is_array( fileList1 ) ) {

  foreach filePath1( keys( fileList1 ) ) {

    vers1 = fileList1[filePath1];

    if( vers1 && version1 = eregmatch( string:vers1, pattern:"^([0-9.]+)" ) ) {

      if( version1[1] =~ "^1\.0" && version_is_less( version:version1[1], test_version:"1.0.6" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version1[1], file_checked:filePath1, fixed_version:"1.0.6" ) + '\n';
      } else if( version1[1] =~ "^1\.1" && version_is_less( version:version1[1], test_version:"1.1.5" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version1[1], file_checked:filePath1, fixed_version:"1.1.5" ) + '\n';
      }
    }
  }
}

if( fileList2 && is_array( fileList2 ) ) {

  foreach filePath2( keys( fileList2 ) ) {

    vers2 = fileList2[filePath2];

    if( vers2 && version2 = eregmatch( string:vers2, pattern:"^([0-9.]+)" ) ) {

      if( version2[1] =~ "^1\.0" && version_is_less( version:version2[1], test_version:"1.0.6" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version2[1], file_checked:filePath2, fixed_version:"1.0.6" ) + '\n';
      } else if( version2[1] =~ "^1\.1" && version_is_less( version:version2[1], test_version:"1.1.5" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version2[1], file_checked:filePath2, fixed_version:"1.1.5" ) + '\n';
      }
    }
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
