# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803082");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2012-5679", "CVE-2012-5680");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-12-21 13:45:50 +0530 (Fri, 21 Dec 2012)");
  script_name("Adobe Photoshop Camera Raw Plug-in Code Execution Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56924");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027872");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-28.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version", "Adobe/Photoshop/MacOSX/Path");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Adobe Photoshop Camera Raw Plug-in version before 7.3 on Windows");
  script_tag(name:"insight", value:"Errors exist within the 'Camera Raw.8bi' plug-in when

  - Parsing a LZW compressed TIFF images can be exploited to cause a buffer
    underflow via a specially crafted LZW code within an image row strip.

  - Allocating memory during TIFF image processing can be exploited to cause
    buffer overflow via a specially crafted image dimensions.");
  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop Camera Raw Plug-in version 7.3 or later.");
  script_tag(name:"summary", value:"Adobe Photoshop Camera Raw Plug-in is prone to code execution vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

photoVer = get_kb_item( "Adobe/Photoshop/MacOSX/Version" );
if( ! photoVer ) exit( 0 );

photoPath = get_kb_item( "Adobe/Photoshop/MacOSX/Path" );
if( photoPath !~ "CS" || photoVer !~ "CS" ) exit( 0 );

adobeVer = eregmatch( pattern:"CS[0-9.]+", string:photoPath );
if( ! isnull( adobeVer[0] ) ) {
  photoVer = adobeVer[0];
} else {
  exit( 0 );
}

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

camrawPath = "/Library/Application\ Support/Adobe/Plug-Ins/" + photoVer + "/File\ Formats/Camera\ Raw.plugin/Contents/Info CFBundleVersion";
camrawVer = chomp( ssh_cmd( socket:sock, cmd:"defaults read " + camrawPath ) );
close( sock );
if( isnull( camrawVer ) || "does not exist" >< camrawVer ) {
  exit( 0 );
}

camrawVer = ereg_replace( pattern:"([a-z])", string:camrawVer, replace:"." );
if( ! isnull( camrawVer ) && version_is_less( version:camrawVer, test_version:"7.3" ) ) {
  report = report_fixed_ver( installed_version:camrawVer, fixed_version:"7.3", install_path:camrawPath );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
