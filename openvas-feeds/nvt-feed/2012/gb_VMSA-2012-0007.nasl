# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103466");
  script_cve_id("CVE-2012-1518");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");
  script_name("VMware ESXi/ESX patches address privilege escalation (VMSA-2012-0007)");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-13 10:53:01 +0100 (Fri, 13 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0007.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0007.");

  script_tag(name:"affected", value:"ESXi 5.0 without patch ESXi500-201203102-SG

  ESXi 4.1 without patch ESXi410-201201402-BG

  ESXi 4.0 without patch ESXi400-201203402-BG

  ESXi 3.5 without patch ESXe350-201203402-T-BG

  ESX 4.1 without patch ESX410-201201401-SG

  ESX 4.0 without patch ESX400-201203401-SG

  ESX 3.5 without patch ESX350-201203402-BG");

  script_tag(name:"insight", value:"VMware hosted products and ESXi/ESX patches address privilege escalation.

  a. VMware Tools Incorrect Folder Permissions Privilege Escalation

  The access control list of the VMware Tools folder is incorrectly set.
  Exploitation of this issue may lead to local privilege escalation on
  Windows-based Guest Operating Systems.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

patches = make_array("4.1.0", "ESXi410-201201402-BG",
                     "4.0.0", "ESXi400-201203402-BG",
                     "5.0.0", "VIB:tools-light:5.0.0-0.10.608089");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
