# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902260");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_cve_id("CVE-2010-3277");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("VMware Products Security Bypass Vulnerability (VMSA-2010-0014) - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41574");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2491");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Sep/1024481.html");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0014.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2010/000105.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to display a malicious file if they
  manage to get their file onto the system prior to installation.");

  script_tag(name:"affected", value:"VMware Player 3.0 before 3.1.2 build 301548

  VMware Workstation 7.0 before 7.1.2 build 301548 on Windows.");

  script_tag(name:"insight", value:"The vulnerability is due to an error in the 'installer', which will
  load an 'index.htm' file located in the current working directory.");

  script_tag(name:"summary", value:"VMWare product(s) are prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to player 3.1.2 build 301548

  Upgrade VMware Workstation 7.1.2 build 301548");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmpVer = get_kb_item("VMware/Player/Win/Ver");
if(vmpVer)
{
  if(version_in_range(version:vmpVer, test_version:"3.0", test_version2:"3.1.1"))
  {
    report = report_fixed_ver(installed_version:vmpVer, vulnerable_range:"3.0 - 3.1.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vmwtnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmwtnVer)
{
  if(version_in_range(version:vmwtnVer, test_version:"7.0", test_version2:"7.1.1")){
    report = report_fixed_ver(installed_version:vmwtnVer, vulnerable_range:"7.0 - 7.1.1");
    security_message(port: 0, data: report);
  }
}
