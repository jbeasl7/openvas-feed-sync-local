# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801144");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3733");
  script_name("VMware Server Directory Traversal Vulnerability (Nov 2009) - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37186");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36842");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3062");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Oct/1023088.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2009/000069.html");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0015.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed", "VMware/Server/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the remote/local attacker to disclose
  sensitive information.");

  script_tag(name:"affected", value:"VMware Server version 2.0.x prior to 2.0.2 Build 203138,
  VMware Server version 1.0.x prior to 1.0.10 Build 203137 on Linux.");

  script_tag(name:"insight", value:"An error exists while handling certain requests can be exploited to download
  arbitrary files from the host system via directory traversal attacks.");

  script_tag(name:"solution", value:"Upgrade the VMWare product(s) according to the referenced vendor announcement.");

  script_tag(name:"summary", value:"VMWare Server is prone to a directory traversal vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

vmserverVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserverVer)
{
  if(version_in_range(version:vmserverVer, test_version:"1.0", test_version2:"1.0.9")||
     version_in_range(version:vmserverVer, test_version:"2.0", test_version2:"2.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
