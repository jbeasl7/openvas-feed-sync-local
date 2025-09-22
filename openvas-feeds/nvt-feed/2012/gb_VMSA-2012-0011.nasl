# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103495");
  script_cve_id("CVE-2012-3288", "CVE-2012-3289");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");
  script_name("VMware ESXi/ESX patches address security issues (VMSA-2012-0011)");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-15 10:02:01 +0100 (Fri, 15 Jun 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0011.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).

  a. VMware Host Checkpoint file memory corruption

  Workaround - None identified

  Mitigation - Do not import virtual machines from untrusted sources.

  b. VMware Virtual Machine Remote Device Denial of Service

  Workaround - None identified

  Mitigation - Users need administrative privileges on the virtual machine in
  order to attach remote devices. - Do not attach untrusted remote devices to a
  virtual machine.");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0011.");

  script_tag(name:"affected", value:"ESXi 5.0 without patch ESXi500-201206401-SG

  ESXi 4.1 without patch ESXi410-201206401-SG

  ESXi 4.0 without patch ESXi400-201206401-SG

  ESXi 3.5 without patch ESXe350-201206401-I-SG

  ESX 4.1 without patch ESX410-201206401-SG

  ESX 4.0 without patch ESX400-201206401-SG

  ESX 3.5 without patch ESX350-201206401-SG");

  script_tag(name:"insight", value:"a. VMware Host Checkpoint file memory corruption

  Input data is not properly validated when loading Checkpoint files. This may
  allow an attacker with the ability to load a specially crafted Checkpoint file
  to execute arbitrary code on the host.

  b. VMware Virtual Machine Remote Device Denial of Service

  A device (e.g. CD-ROM, keyboard) that is available to a virtual machine while
  physically connected to a system that does not run the virtual machine is
  referred to as a remote device.

  Traffic coming from remote virtual devices is incorrectly handled. This may
  allow an attacker who is capable of manipulating the traffic from a remote
  virtual device to crash the virtual machine.");

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

patches = make_array("4.1.0", "ESXi410-201206401-SG",
                     "4.0.0", "ESXi400-201206401-SG",
                     "5.0.0", "VIB:esx-base:5.0.0-1.16.721882");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
