# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834204");
  script_version("2024-08-13T09:47:32+0000");
  script_cve_id("CVE-2024-37085");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-13 09:47:32 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-31 14:46:29 +0000 (Wed, 31 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-06-26 11:32:34 +0530 (Wed, 26 Jun 2024)");
  script_name("VMware ESXi Authentication Bypass Vulnerability (VMSA-2024-0013)");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24505");
  script_xref(name:"URL", value:"https://knowledge.broadcom.com/external/article/369707/");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"VMware ESXi is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling of authentication
  tokens.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to bypass
  authentication mechanisms.");

  script_tag(name:"affected", value:"VMware ESXi 7.0.x and 8.0.x prior to ESXi80U3-24022510.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.

  Notes:

  - No patch for ESXi 7.0.x is planned by the vendor

  - Please see the references for possible workarounds

  - Please create an override for this result if only the workarounds have been applied");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!version = get_kb_item("VMware/ESX/version"))
  exit(0);

if(version =~ "^7\.0\." || version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: 0, data: report);
  exit(0);
}

# https://docs.vmware.com/en/VMware-vSphere/8.0/rn/vsphere-esxi-803-release-notes/index.html
patches = make_array("8.0.3", "VIB:esx-base:8.0.3-0.0.24022510");

if(!patches[version])
  exit(99);

if(report = esxi_patch_missing(esxi_version: version, patch: patches[version])) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
