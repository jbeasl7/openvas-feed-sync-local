# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vsphere_data_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811319");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-4914", "CVE-2017-4917");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-08-30 16:55:06 +0530 (Wed, 30 Aug 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("VMware vSphere Data Protection (VDP) Multiple Vulnerabilities");

  script_tag(name:"summary", value:"VMware vSphere Data Protection (VDP) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - A deserialization issue.

  - Storing vCenter Server credentials locally using reversible encryption.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute commands on the appliance, also can obtain password
  information.");

  script_tag(name:"affected", value:"VMware vSphere Data Protection (VDP)
  versions 6.1.x, 6.0.x, 5.8.x, and 5.5.x");

  script_tag(name:"solution", value:"Upgrade to VMware vSphere Data Protection
  (VDP) 6.1.4, 6.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0010.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98936");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98939");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vmware_vsphere_data_protection_version.nasl");
  script_mandatory_keys("vmware/vSphere_Data_Protection/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(((appVer =~ "^5\.5\.") || (appVer =~ "^5\.8\.") || (appVer =~ "^6\.0\."))
     && (version_is_less(version:appVer, test_version:"6.0.5"))){
  fix = "6.0.5";
}
else if((appVer =~ "^6\.1\.") && (version_is_less(version:appVer, test_version:"6.1.4"))){
  fix = "6.1.4";
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
