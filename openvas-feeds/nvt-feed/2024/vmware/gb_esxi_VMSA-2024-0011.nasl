# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834028");
  script_version("2025-03-04T05:38:25+0000");
  script_cve_id("CVE-2024-22273");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-01 02:36:21 +0000 (Sat, 01 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-05-23 11:43:50 +0530 (Thu, 23 May 2024)");
  script_name("VMware ESXi Out-of-bounds read/write Vulnerability (VMSA-2024-0011)");

  script_tag(name:"summary", value:"VMware ESXi is prone to an out-of-bounds
  read/write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out of bounds
  read/write error exists in VMware ESXi.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code and cause denial of service attacks.");

  script_tag(name:"affected", value:"VMware ESXi 7.0 before ESXi70U3sq-23794019
  and 8.0 before ESXi80U2sb-23305545.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24308");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");
  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if (!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if (!version = get_kb_item("VMware/ESX/version"))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: 0, data: report);
  exit(0);
} else if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: 0, data: report);
  exit(0);
}

# https://docs.vmware.com/en/VMware-vSphere/7.0/rn/vsphere-esxi-70u3q-release-notes/index.html#Resolved%20Issues-ESXi-7.0U3sq-23794019-standard
# https://docs.vmware.com/en/VMware-vSphere/8.0/rn/vsphere-esxi-80u2b-release-notes/index.html#Resolved%20Issues-ESXi-8.0U2sb-23305545-standard
patches = make_array("7.0.0", "VIB:esx-base:7.0.3-0.120.23794019",
                     "8.0.0", "VIB:esx-base:8.0.2-0.25.23305545");

if (!patches[version])
  exit(99);

if (report = esxi_patch_missing(esxi_version: version, patch: patches[version])) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
