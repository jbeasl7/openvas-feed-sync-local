# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105190");
  script_cve_id("CVE-2014-8370", "CVE-2015-1043", "CVE-2015-1044", "CVE-2014-3513", "CVE-2014-3567", "CVE-2014-3566", "CVE-2014-3568", "CVE-2014-3660");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("2023-11-02T05:05:26+0000");
  script_name("VMware ESXi updates address security issues (VMSA-2015-0001)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0001.html");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. VMware ESXi, Workstation, Player, and Fusion host privilege escalation vulnerability

  VMware ESXi, Workstation, Player and Fusion contain an arbitrary file write issue. Exploitation this issue may allow for privilege
  escalation on the host.

  c. VMware ESXi, Workstation, and Player Denial of Service vulnerability

  VMware ESXi, Workstation, and Player contain an input validation issue in VMware Authorization process (vmware-authd). This issue
  may allow for a Denial of Service of the host. On VMware ESXi and on Workstation running on Linux the Denial of Service would be
  partial.

  d. Update to VMware vCenter Server and ESXi for OpenSSL 1.0.1 and 0.9.8 package

  The OpenSSL library is updated to version 1.0.1j or 0.9.8zc to resolve multiple security issues.

  e. Update to ESXi libxml2 package

  The libxml2 library is updated to version libxml2-2.7.6-17 to resolve a security issue.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware ESXi address several security issues.");

  script_tag(name:"affected", value:"ESXi 5.5 without patch ESXi550-201403102-SG, ESXi550-201501101-SG

  ESXi 5.1 without patch ESXi510-201404101-SG

  ESXi 5.0 without patch ESXi500-201405101-SG");

  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2015-01-30 12:05:44 +0100 (Fri, 30 Jan 2015)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

patches = make_array("5.0.0", "VIB:esx-base:5.0.0-3.47.1749766",
                     "5.1.0", "VIB:esx-base:5.1.0-2.27.1743201",
                     "5.5.0", "VIB:esx-base:5.5.0-2.51.2352327");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
