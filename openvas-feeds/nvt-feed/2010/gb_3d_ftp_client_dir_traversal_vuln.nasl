# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902234");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)");
  script_cve_id("CVE-2010-3102");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("3D FTP Client Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://vuln.sg/3dftp801-en.html");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/Aug/227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/513244");
  script_xref(name:"URL", value:"http://osdir.com/ml/bugtraq.security/2010-08/msg00226.html");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/directory_traversal_in_3d_ftp_client.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to an error in handling of certain crafted
file names. It does not properly sanitise filenames containing directory
traversal sequences that are received from an FTP server.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to version 9.03 or later.");
  script_tag(name:"summary", value:"3D FTP Client is prone to a directory traversal vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to write files into
a user's Startup folder to execute malicious code when the user logs on.");
  script_tag(name:"affected", value:"3D FTP Client 9.0 build 2 (9.0.2) and prior.");
  script_xref(name:"URL", value:"http://3dftp.com/download_3dftp.htm");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ftpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("3D-FTP" >< ftpName)
  {
    ftpVer = registry_get_sz(key: key + item , item:"DisplayVersion");
    if(ftpVer != NULL)
    {
      if(version_is_less_equal(version:ftpVer, test_version:"9.0.2"))
      {
        report = report_fixed_ver(installed_version:ftpVer, vulnerable_range:"Less than or equal to 9.0.2");
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}
