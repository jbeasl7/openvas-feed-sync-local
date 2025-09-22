# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902173");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-29 10:23:16 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2009-4811");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("VMware Authorization Service DoS Vulnerability (VMSA-2010-0007) - Windows");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0007.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2010-04/0077.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2010/000090.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2010-04/0121.html");
  script_xref(name:"URL", value:"http://www.vmware.com/resources/techresources/726");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code on the
  affected application and causes the Denial of Service.");

  script_tag(name:"affected", value:"VMware Server 2.x

  VMware ACE 2.6 before 2.6.1 build 227600 and 2.5.x before 2.5.4 build 246459

  VMware Player 3.0 before 3.0.1 build 227600 and 2.5.x before 2.5.4 build 246459

  VMware Workstation 7.0 before 7.0.1 build 227600 and 6.5.x before 6.5.4 build 246459");

  script_tag(name:"insight", value:"The vulnerability is due to an error in the VMware Authorization
  Service when processing login requests. This can be exploited to terminate
  the 'vmware-authd' process via 'USER' or 'PASS' strings containing '\xFF'
  characters, sent to TCP port 912.");

  script_tag(name:"summary", value:"VMWare product(s) are prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to player  3.0.1 build 227600 or 2.5.4 build 246459,

  Upgrade to VMware ACE  2.6.1 build 227600 or 2.5.4 build 246459

  Upgrade VMware Workstation 7.0.1 build 227600 and 6.5.4 build 246459

  Apply the workaround for VMware Server version 2.x described in the referenced techresource.");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmpVer = get_kb_item("VMware/Player/Win/Ver");
if(vmpVer)
{
  if(version_is_equal(version:vmpVer, test_version:"3.0") ||
     version_in_range(version:vmpVer, test_version:"2.5", test_version2:"2.5.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmwtnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmwtnVer)
{
  if(version_is_equal(version:vmwtnVer, test_version:"7.0") ||
     version_in_range(version:vmwtnVer, test_version:"6.0", test_version2:"6.5.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

aceVer = get_kb_item("VMware/ACE/Win/Ver");
if(aceVer)
{
  if(version_is_equal(version:aceVer, test_version:"2.6") ||
     version_in_range(version:aceVer, test_version:"2.5", test_version2:"2.5.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

vmserVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserVer)
{
  if(vmserVer =~ "^2\..+"){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
