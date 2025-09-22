# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810548");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2015-3650");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-02-08 16:20:40 +0530 (Wed, 08 Feb 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Workstation Invalid DACL Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"VMware Workstation is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in 'vmware-vmx.exe'
  which does not provide a valid DACL pointer during the setup of the
  vprintproxy.exe process.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to gain escalated privileges on the host by injecting a thread.
  and execute code in the context of this process.");

  script_tag(name:"affected", value:"VMware Workstation version 10.x before
  10.0.7 and 11.x before 11.1.1 before on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Workstation version
  10.0.7 or 11.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75686");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0005.html");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Workstation/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^10\.")
{
  if(version_is_less(version:vmwareVer, test_version:"10.0.7"))
  {
    fix = "10.0.7";
    VULN = TRUE;
  }
}

else if(vmwareVer =~ "^11\.")
{
  if(version_is_less(version:vmwareVer, test_version:"11.1.1"))
  {
    fix = "11.1.1";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vmwareVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
