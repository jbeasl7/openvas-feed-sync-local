# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800003");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-25 10:10:31 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2098");
  script_xref(name:"CB-A", value:"08-0087:");
  script_name("VMCI/HGFS VmWare Code Execution Vulnerability (VMSA-2008-0008) - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30476/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29443");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2008-0008.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary
  code on the affected system and local users could bypass certain
  security restrictions or can gain escalated privileges.");

  script_tag(name:"summary", value:"VMWare product(s) are prone to an arbitrary code execution vulnerability.");

  script_tag(name:"affected", value:"VMware Player 2.0.x - 2.0.3 on Linux

  VMware Workstation 6.0.x - 6.0.3 on Linux");

  script_tag(name:"solution", value:"Upgrade VMware to:

  VMware Workstation 6.0.4 or later

  VMware Player 2.0.4 or later.");

  script_tag(name:"insight", value:"VMware Host Guest File System (HGFS) shared folders feature allows users to
  transfer data between a guest operating system and the host operating system.
  A heap buffer overflow exists in VMware HGFS which allows guest system to
  execute code in the context of vmx process on the host.
  The issue exists only when VMWare system has shared folder enabled.

  Successful exploitation requires that the vix.inGuest.enable configuration
  value is enabled");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

playerVer = get_kb_item("VMware/Player/Linux/Ver");
if(playerVer)
{
  if(ereg(pattern:"^2\.0(\.[0-3])?($|[^.0-9])", string:playerVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

wrkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(wrkstnVer)
{
  if(ereg(pattern:"^6\.0(\.[0-3])?($|[^.0-9])", string:wrkstnVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}