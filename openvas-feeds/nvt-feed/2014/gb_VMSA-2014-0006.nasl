# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105044");
  script_cve_id("CVE-2014-0224", "CVE-2014-0198", "CVE-2010-5298", "CVE-2014-3470");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_name("VMware ESXi updates address OpenSSL security vulnerabilities (VMSA-2014-0006)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 16:40:00 +0000 (Tue, 28 Jul 2020)");
  script_tag(name:"creation_date", value:"2014-06-13 11:04:01 +0100 (Fri, 13 Jun 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. OpenSSL update for multiple products.

  OpenSSL libraries have been updated in multiple products to versions 0.9.8za and 1.0.1h
  in order to resolve multiple security issues.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware product updates address OpenSSL security vulnerabilities.");

  script_tag(name:"affected", value:"ESXi 5.5 prior to ESXi550-201406401-SG

  ESXi 5.1 without patch ESXi510-201406401-SG

  ESXi 5.0 without patch ESXi500-201407401-SG");

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

patches = make_array("5.5.0", "VIB:esx-base:5.5.0-1.18.1881737",
                     "5.1.0", "VIB:esx-base:5.1.0-2.29.1900470",
                     "5.0.0", "VIB:esx-base:5.0.0-3.50.1918656");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
