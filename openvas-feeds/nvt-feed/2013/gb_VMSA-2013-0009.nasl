# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103749");
  script_cve_id("CVE-2013-0169", "CVE-2013-0166", "CVE-2013-0338", "CVE-2013-2116", "CVE-2013-0268", "CVE-2013-0871");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2023-07-27T05:05:08+0000");
  script_name("VMware ESXi/ESX updates to third party libraries (VMSA-2013-0009)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0009.html");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-07 14:04:01 +0100 (Wed, 07 Aug 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. ESX userworld update for OpenSSL library

  The userworld OpenSSL library is updated to version openssl-0.9.8y to resolve
  multiple security issues.

  b. Service Console (COS) update for OpenSSL library

  The Service Console updates for OpenSSL library is updated to version
  openssl-0.9.8e-26.el5_9.1 to resolve multiple security issues.

  c. ESX Userworld and Service Console (COS) update for libxml2 library

  The ESX Userworld and Service Console libxml2 library is updated to version
  libxml2-2.6.26-2.1.21.el5_9.1 and libxml2-python-2.6.26-2.1.21.el5_9.1. to
  resolve a security issue.

  d. Service Console (COS) update for GnuTLS library

  The ESX service console GnuTLS RPM is updated to version
  gnutls-1.4.1-10.el5_9.1 to resolve a security issue.

  e. ESX third party update for Service Console kernel

  The ESX Service Console Operating System (COS) kernel is updated to
  kernel-2.6.18-348.3.1.el5 which addresses several security issues in the COS kernel.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware has updated several third party libraries in ESX and ESXi to address multiple security vulnerabilities.");

  script_tag(name:"affected", value:"VMware ESXi 4.1 without patch ESXi410-201307001

  VMware ESX 4.1 without patch ESX410-201307001

  VMware ESXi 5.0 without Update 3

  VMware ESXi 4.0 without patch ESXi400-201310001

  VMware ESX 4.0 without patch ESX400-201310001");

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

patches = make_array("4.1.0", "ESXi410-201307401-SG",
                     "4.0.0", "ESXi400-201310401-SG",
                     "5.0.0", "VIB:esx-base:5.0.0-2.38.1311177");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
