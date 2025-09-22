# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900206");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-27 11:53:45 +0200 (Wed, 27 Aug 2008)");
  script_cve_id("CVE-2008-3734");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_name("Ipswitch WS FTP Client Format String Vulnerability");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://secunia.com/advisories/31504/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30720");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/44512");
  script_tag(name:"summary", value:"WS FTP Client is prone to a format string vulnerability.");
  script_tag(name:"insight", value:"Issue is due to a format string error when processing responses
  of the FTP server.");
  script_tag(name:"affected", value:"Ipswitch WS FTP Home/Professional 2007 and prior versions.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Ipswitch WS FTP Home/Professional version 12 or later.");
  script_tag(name:"impact", value:"Successful exploitation will allow execution of arbitrary code
  on the vulnerable system or cause the application to crash by tricking
  a user into connecting to a malicious ftp server.");

  exit(0);
}


 include("smb_nt.inc");
 include("secpod_smb_func.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 wsFtpDir = registry_get_sz(key:"SOFTWARE\Ipswitch\WS_FTP",
                            item:"Dir");

 if(!wsFtpDir)
 {
        wsFtpDir = registry_get_sz(key:"SOFTWARE\Ipswitch\WS_FTP Home",
                                   item:"Dir");
        if(!wsFtpDir){
                exit(0);
        }
        wsFtpHome = TRUE;
 }

 fileVer = GetVersionFromFile(file:wsFtpDir + "\wsftpgui.exe", verstr:"prod");

 if(!fileVer){
    exit(0);
 }

 if(wsFtpHome)
 {
        if(egrep(pattern:"^([01][0-9][0-9][0-9]\..*|200[0-6]\..*|" +
                         "2007\.0\.0\.[0-2])$", string:fileVer)){
                security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
 }
 else
 {
        if(egrep(pattern:"^([01][0-9][0-9][0-9]\..*|200[0-6]\..*|" +
                         "2007\.[01]\.0\.0)$", string:fileVer)){
                security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
 }
