# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801558");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4294");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Products Memory Corruption and Buffer Overflow Vulnerability (VMSA-2010-0018) - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45169");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0018.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2010/000112.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to corrupt heap
memory by tricking a user into visiting a malicious website or playing a
malicious file.");
  script_tag(name:"affected", value:"VMware Server version  2.x
VMware Player 2.5.x before 2.5.5 build 246459 and 3.x before 3.1.2 build 301548
VMware Workstation 6.5.x before 6.5.5 build 328052 and 7.x before 7.1.2 build 301548");
  script_tag(name:"insight", value:"The flaw is due to the VMnc codec 'vmnc.dll' driver which does
not properly verify the size when handling 'ICM_DECOMPRESS' driver messages,
which can be exploited to corrupt heap memory.");
  script_tag(name:"summary", value:"VMWare products are prone to memory corruption and buffer overflow vulnerabilities.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"2.5", test_version2:"2.5.4") ||
     version_in_range(version:vmplayerVer, test_version:"3.0", test_version2:"3.1.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"6.5", test_version2:"6.5.4") ||
     version_in_range(version:vmworkstnVer, test_version:"7.0", test_version2:"7.1.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# VMware Server
vmserVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserVer)
{
  if(vmserVer =~ "^2.*"){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
