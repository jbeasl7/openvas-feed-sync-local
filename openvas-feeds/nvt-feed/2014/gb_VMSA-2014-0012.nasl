# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105133");
  script_cve_id("CVE-2014-3797", "CVE-2014-8371", "CVE-2013-2877", "CVE-2014-0191", "CVE-2014-0015",
                "CVE-2014-0138", "CVE-2013-1752", "CVE-2013-4238");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("2023-07-27T05:05:08+0000");
  script_name("VMware ESXi product updates address security vulnerabilities (VMSA-2014-0012)");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-05 11:31:51 +0100 (Fri, 05 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0012.html");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. VMware vCSA cross-site scripting vulnerability
  VMware vCenter Server Appliance (vCSA) contains a vulnerability that may
  allow for Cross Site Scripting. Exploitation of this vulnerability in
  vCenter Server requires tricking a user to click on a malicious link or
  to open a malicious web page while they are logged in into vCenter.

  b. vCenter Server certificate validation issue
  vCenter Server does not properly validate the presented certificate
  when establishing a connection to a CIM Server residing on an ESXi
  host. This may allow for a Man-in-the-middle attack against the CIM
  service.

  c. Update to ESXi libxml2 package
  libxml2 is updated to address multiple security issues.

  d. Update to ESXi Curl package
  Curl is updated to address multiple security issues.

  e. Update to ESXi Python package
  Python is updated to address multiple security issues.

  f. vCenter and Update Manager, Oracle JRE 1.6 Update 81

  Oracle has documented the CVE identifiers that are addressed in JRE
  1.6.0 update 81 in the Oracle Java SE Critical Patch Update Advisory of July 2014.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware vSphere product updates address a Cross Site Scripting issue, a certificate validation
  issue and security vulnerabilities in third-party libraries.");

  script_tag(name:"affected", value:"VMware ESXi 5.1 without patch ESXi510-201412101-SG.");

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

patches = make_array("5.1.0", "VIB:esx-base:5.1.0-3.50.2323231");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
