# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:vmware:vsphere_data_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810683");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-4632");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-11 12:14:20 +0530 (Tue, 11 Apr 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("VMware vSphere Data Protection (VDP) Man-in-the-Middle Attack Vulnerability");

  script_tag(name:"summary", value:"VMware vSphere Data Protection (VDP) is prone to a man in the middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper verification
  of X.509 certificates from vCenter Server SSL servers.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to spoof servers, and bypass intended backup and restore access
  restrictions, via a crafted certificate.");

  script_tag(name:"affected", value:"VMware vSphere Data Protection (VDP) 5.1,
  5.5 before 5.5.9, and 5.8 before 5.8.1");

  script_tag(name:"solution", value:"Upgrade to VMware vSphere Data Protection
  (VDP) 5.5.9 or 5.8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0002.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72367");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031664");

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

if(appVer =~ "^5\.1\.")
{
  VULN = TRUE;
  fix = "5.5.9 or 5.8.1";
}
else if((appVer =~ "^5\.5\.") && (version_is_less(version:appVer, test_version:"5.5.9")))
{
  VULN = TRUE;
  fix = "5.5.9";
}
else if((appVer =~ "^5\.8\.") && (version_is_less(version:appVer, test_version:"5.8.1")))
{
  VULN = TRUE;
  fix = "5.8.1";
}

if(VULN)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
