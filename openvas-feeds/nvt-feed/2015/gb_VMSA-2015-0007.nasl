# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105393");
  script_cve_id("CVE-2015-5177", "CVE-2015-2342", "CVE-2015-1047");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-11-02T05:05:26+0000");
  script_name("VMware ESXi OpenSLP Remote Code Execution (VMSA-2015-0007)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0007.html");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"- VMware ESXi OpenSLP Remote Code Execution

  VMware ESXi contains a double free flaw in OpenSLP's SLPDProcessMessage() function. Exploitation of
  this issue may allow an unauthenticated attacker to execute code remotely on the ESXi host.

  - VMware vCenter Server JMX RMI Remote Code Execution

  VMware vCenter Server contains a remotely accessible JMX RMI service that is not securely configured.
  An unauthenticated remote attacker that is able to connect to the service may be able use it to execute
  arbitrary code on the vCenter server.

  - VMware vCenter Server vpxd denial-of-service vulnerability

  VMware vCenter Server does not properly sanitize long heartbeat messages. Exploitation of this issue may
  allow an unauthenticated attacker to create a denial-of-service condition in the vpxd service.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vCenter and ESXi updates address critical security issues.");

  script_tag(name:"affected", value:"VMware ESXi 5.5 without patch ESXi550-201509101

  VMware ESXi 5.1 without patch ESXi510-201510101

  VMware ESXi 5.0 without patch ESXi500-201510101");

  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-12 01:29:00 +0000 (Sun, 12 Aug 2018)");
  script_tag(name:"creation_date", value:"2015-10-05 10:37:34 +0200 (Mon, 05 Oct 2015)");
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

patches = make_array("5.0.0", "VIB:esx-base:5.0.0-3.70.3088986",
                     "5.1.0", "VIB:esx-base:5.1.0-3.57.3021178",
                     "5.5.0", "VIB:esx-base:5.5.0-2.65.3029837");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
