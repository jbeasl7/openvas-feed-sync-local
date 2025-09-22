# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:messenger_plus%21_live";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900810");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_cve_id("CVE-2009-2544");
  script_name("Marcelo Costa FileServer Component Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9093");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/382773.php");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ms_win_live_messenger_detect.nasl");
  script_mandatory_keys("MS/MessengerPlus/Installed", "MS/MessengerPlus/Path");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause Directory
Traversal attacks on the affected product.");
  script_tag(name:"affected", value:"Marcelo Costa FileServer version 1.0");
  script_tag(name:"insight", value:"Error in the FileServer component which may allows remote
authenticated users to list arbitrary directories and read arbitrary files via
a .. (dot dot) in a pathname.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Marcelo Costa FileServer with Windows Live Messenger and Messenger Plus! Live is prone to a directory traversal vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
version  = infos["version"];
plusPath = infos["location"];
if( ! plusPath ) exit( 0 );

if( version =~ "^4\..*" )
{
  fsPath = NULL;
  if("\Uninstall.exe" >< plusPath)
    fsPath = plusPath - "\Uninstall.exe" + "\Scripts\FileServer\fsVersion.txt";
  else if("\MsgPlus.exe" >< plusPath)
    fsPath = plusPath - "\MsgPlus.exe" + "\Scripts\FileServer\fsVersion.txt";

  if(!isnull(fsPath))
  {
    fileSrvTxt = smb_read_file(fullpath:fsPath, offset:0, count:100);

    if(isnull(fileSrvTxt)){
      exit(0);
    }
    costaVer = egrep(pattern:"[0-9.]+", string:fileSrvTxt);

    if(costaVer && version_is_equal(version:costaVer, test_version:"1.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
