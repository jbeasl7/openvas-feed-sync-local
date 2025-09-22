# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103778");
  script_cve_id("CVE-2013-1661");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("2023-07-27T05:05:08+0000");
  script_name("VMware ESXi/ESX updates to third party libraries (VMSA-2013-0011)");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0011.html");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-02 14:04:01 +0100 (Mon, 02 Sep 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"VMware ESXi and ESX NFC Protocol Unhandled Exception

  VMware ESXi and ESX contain a vulnerability in the handling of
  the Network File Copy (NFC) protocol. To exploit this
  vulnerability, an attacker must intercept and modify the NFC
  traffic between ESXi/ESX and the client. Exploitation of the
  issue may lead to a Denial of Service.

  To reduce the likelihood of exploitation, vSphere components should
  be deployed on an isolated management network.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware has updated VMware ESXi and ESX to address a vulnerability in
  an unhandled exception in the NFC protocol handler.");

  script_tag(name:"affected", value:"VMware ESXi 5.1 without patch ESXi510-201307101

  VMware ESXi 5.0 without patch ESXi500-201308101

  VMware ESXi 4.1 without patch ESXi410-201304401

  VMware ESXi 4.0 without patch ESXi400-201305401

  VMware ESX 4.1 without patch ESX410-201304401

  VMware ESX 4.0 without patch ESX400-201305401");

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

patches = make_array("4.0.0", "ESXi400-201305401-SG",
                     "4.1.0", "ESXi410-201304401-SG",
                     "5.0.0", "VIB:tools-light:5.0.0-2.35.1254542",
                     "5.1.0", "VIB:tools-light:5.1.0-1.16.1157734");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
