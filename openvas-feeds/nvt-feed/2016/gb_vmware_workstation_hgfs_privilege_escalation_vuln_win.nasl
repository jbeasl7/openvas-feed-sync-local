# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809021");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2016-5330");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-05 16:33:00 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-09-01 10:20:57 +0530 (Thu, 01 Sep 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Workstation 'HGFS' Feature Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"VMware Workstation is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a DLL hijacking
  vulnerability present in the VMware Tools 'Shared Folders' (HGFS) feature
  running on Microsoft Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  local users to gain extra privileges.");

  script_tag(name:"affected", value:"VMware Workstation version 12.1.x before
  12.1.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Workstation version
  12.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92323");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^(12\.1)")
{
  if(version_is_less(version:vmwareVer, test_version:"12.1.1"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"12.1.1");
    security_message(data:report);
    exit(0);
  }
}
