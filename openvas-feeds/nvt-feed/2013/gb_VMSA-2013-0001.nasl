# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103655");
  script_cve_id("CVE-2013-1405", "CVE-2011-3102", "CVE-2012-2807", "CVE-2012-4244", "CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-27T05:05:08+0000");
  script_name("VMware ESXi/ESX security updates for the authentication service and third party libraries (VMSA-2013-0001)");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-04 11:02:01 +0100 (Mon, 04 Feb 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2013-0001.");

  script_tag(name:"affected", value:"ESXi 4.1 without patch ESXi410-201301401-SG

  ESXi 4.0 without patches ESXi400-201302401-SG and ESXi400-201302403-SG

  ESX 4.1 without patches ESX410-201301401-SG, ESX410-201301402-SG, ESX410-201301403-SG and ESX410-201301405-SG");

  script_tag(name:"insight", value:"a. VMware vSphere client-side authentication memory corruption vulnerability

  VMware vCenter Server, vSphere Client, and ESX contain a vulnerability in the
  handling of the management authentication protocol. To exploit this
  vulnerability, an attacker must convince either vCenter Server,
  vSphere Client or ESX to interact with a malicious server as a
  client. Exploitation of the issue may lead to code execution on the client
  system.

  To reduce the likelihood of exploitation, vSphere components should be
  deployed on an isolated management network.

  b. Update to ESX/ESXi libxml2 userworld and service console

  The ESX/ESXi userworld libxml2 library has been updated to resolve
  multiple security issues. Also, the ESX service console libxml2
  packages are updated to the following versions:

  libxml2-2.6.26-2.1.15.el5_8.5

  libxml2-python-2.6.26-2.1.15.el5_8.5

  c. Update to ESX service console bind packages

  The ESX service console bind packages are updated to the following versions:

  bind-libs-9.3.6-20.P1.el5_8.2

  bind-utils-9.3.6-20.P1.el5_8.2

  d. Update to ESX service console libxslt package

  The ESX service console libxslt package is updated to version
  libxslt-1.1.17-4.el5_8.3 to resolve multiple security issues.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0001.html");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

patches = make_array("4.1.0", "ESXi410-201301401-SG",
                     "4.0.0", "ESXi400-201302403-SG");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
