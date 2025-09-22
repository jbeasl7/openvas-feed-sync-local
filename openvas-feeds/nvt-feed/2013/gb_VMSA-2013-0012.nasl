# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103816");
  script_cve_id("CVE-2013-5970", "CVE-2013-5971");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("2024-02-08T14:36:53+0000");
  script_name("VMware ESXi/ESX Multiple Vulnerabilities (VMSA-2013-0012)");

  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2013-0012.html");

  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-10-21 10:04:01 +0100 (Mon, 21 Oct 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"summary", value:"VMware has updated ESXi and ESX to address multiple security
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. VMware ESXi and ESX contain a vulnerability in hostd-vmdb.

  To exploit this vulnerability, an attacker must intercept and modify the management traffic.
  Exploitation of the issue may lead to a Denial of Service of the hostd-vmdb service.

  To reduce the likelihood of exploitation, vSphere components should be deployed on an isolated
  management network.

  b. VMware vSphere Web Client Server Session Fixation Vulnerability

  The VMware vSphere Web Client Server contains a vulnerability in the handling of session IDs. To
  exploit this vulnerability, an attacker must know a valid session ID of an authenticated user.
  Exploitation of the issue may lead to Elevation of Privilege.

  To reduce the likelihood of exploitation, vSphere components should be deployed on an isolated
  management network.

  c. vCenter and Update Manager, Oracle JRE update 1.6.0_51.

  Oracle JRE is updated to version 1.6.0_51, which addresses multiple security issues that existed
  in earlier releases of Oracle JRE.

  Oracle has documented the CVE identifiers that are addressed in JRE 1.6.0_51 in the Oracle Java SE
  Critical Patch Update Advisory of June 2013. The References section provides a link to this
  advisory.");

  script_tag(name:"affected", value:"VMware ESXi 5.0 without patch ESXi500-201310101-SG

  VMware ESXi 4.1 without patch ESXi410-201307401-SG

  VMware ESXi 4.0 without patch ESXi400-201305401-SG

  VMware ESX 4.1 without patch ESX410-201307401-SG

  VMware ESX 4.0 without patch ESX400-201305401-SG");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

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
                     "4.1.0", "ESXi410-201307401-SG",
                     "5.0.0", "VIB:esx-base:5.0.0-2.38.1311177");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
