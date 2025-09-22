# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802393");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-5059");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-07 18:05:02 +0530 (Tue, 07 Feb 2012)");
  script_name("Final Draft Script File Parsing Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47044");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18184/");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Final_Draft-Multiple_Stack_Buffer_Overflows.pdf");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash.");
  script_tag(name:"affected", value:"Final Draft version 8.0 before 8.02");
  script_tag(name:"insight", value:"The flaws are due to an error when parsing certain tag elements like
  'Word', 'Transition', 'Location', 'Extension', 'SceneIntro', 'TimeOfDay',
  and 'Character' within a '.fdx' or '.fdxtscript' files, which can be
  exploited to cause a buffer overflow via files with overly long tag elements.");
  script_tag(name:"solution", value:"Upgrade to Final Draft Version 8.02 or later.");
  script_tag(name:"summary", value:"Final Draft is prone to multiple buffer overflow vulnerabilities.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Final Draft";
if(!registry_key_exists(key:key)) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  fdraftname = registry_get_sz(key:key + item, item:"DisplayName");
  if("Final Draft" >< fdraftname)
  {
    fdraftVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(!isnull(fdraftVer) && fdraftVer =~ "^8.*")
    {
      if(version_is_less(version:fdraftVer, test_version:"8.0.2"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
