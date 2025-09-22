# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800161");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0388", "CVE-2010-0389");
  script_name("Sun Java System Web Server Denial of Service Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37910");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-webdav.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-admin.html");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to cause a denial of service
  via HTTP request that lacks a method token or format string specifiers
  in PROPFIND request.");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 6 on Windows.
  Sun Java System Web Server version 7.0 update 7 on Windows.");

  script_tag(name:"insight", value:"- Format string vulnerability in the WebDAV implementation in webservd that
  can be exploited to cause denial of service via format string specifiers
  in the encoding attribute of the XML declaration in a PROPFIND request.

  - An unspecified error in admin server that can be exploited to cause
  denial of service via an HTTP request that lacks a method token.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Sun Java Web Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
sjswsPath = registry_get_sz( key:key + "Sun Java System Web Server", item:"UninstallString" );
if( ! sjswsPath ) exit( 0 );

sjswsPath = ereg_replace( pattern:'\"(.*)\"', replace:"\1", string:sjswsPath );
sjswsPath = sjswsPath - "\bin\uninstall.exe" + "\setup\WebServer.inf";

fileData = smb_read_file(fullpath:sjswsPath, offset:0, count:500 );
if( ! fileData ) exit( 0 );

sjswsVer = eregmatch( pattern:"PRODUCT_VERSION=([0-9.]+)", string:fileData );
sjswsUpdateVer = eregmatch( pattern:"PRODUCT_SP_VERSION=([0-9]+)", string:fileData );

if( ! isnull( sjswsVer[1] ) ) {
  if( ! isnull( sjswsUpdateVer ) ) {
    sjswsFullVer = sjswsVer[1] + "." + sjswsUpdateVer[1];
  } else {
    sjswsFullVer = sjswsVer[1] + "." + "0";
  }
}

if( sjswsFullVer =~ "^7\.0" ) {
  if( version_is_equal( version:sjswsFullVer, test_version:"7.0.6" ) ||
      version_is_equal( version:sjswsFullVer, test_version:"7.0.7" ) ) {
    report = report_fixed_ver( installed_version:sjswsFullVer, fixed_version:"WillNotFix", file_checked:sjswsPath );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );