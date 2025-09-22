# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801274");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_cve_id("CVE-2010-3130");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("TechSmith Snagit Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41124");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14764/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code and conduct DLL hijacking attacks.");
  script_tag(name:"affected", value:"TechSmith Snagit Version 10 (Build 788)");
  script_tag(name:"insight", value:"This flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers
to execute arbitrary code by tricking a user into opening a file from a
network share.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"TechSmith Snagit is prone to insecure library loading vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\TechSmith\SnagIt\")){
    exit(0);
}

snagPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\SnagIt32.exe", item:"Path");
if(!snagPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:snagPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:snagPath +
                            "\SnagIt32.exe");

snagVer = GetVer(share:share, file:file);

if(snagVer != NULL)
{
  if(version_is_equal(version:snagVer, test_version: "10.0.0.788")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
