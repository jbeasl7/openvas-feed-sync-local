# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103627");
  script_cve_id("CVE-2012-6324", "CVE-2012-6325", "CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2011-1089", "CVE-2011-4609", "CVE-2012-0864", "CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");
  script_name("VMware ESXi/ESX security updates (VMSA-2012-0018)");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-27 10:42:13 +0100 (Thu, 27 Dec 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0018.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0018.");

  script_tag(name:"affected", value:"VMware ESXi 5.1 without patch ESXi510-201212101

  VMware ESXi 5.0 without patch ESXi500-201212101");

  script_tag(name:"insight", value:"a. vCenter Server Appliance directory traversal

  The vCenter Server Appliance (vCSA) contains a directory traversal vulnerability that allows an
  authenticated remote user to retrieve arbitrary files. Exploitation of this issue may expose
  sensitive information stored on the server.

  b. vCenter Server Appliance arbitrary file download

  The vCenter Server Appliance (vCSA) contains an XML parsing vulnerability that allows an
  authenticated remote user to retrieve arbitrary files. Exploitation of this issue may
  expose sensitive information stored on the server.

  c. Update to ESX glibc package

  The ESX glibc package is updated to version glibc-2.5-81.el5_8.1 to resolve multiple security issues.");

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

patches = make_array("5.0.0", "VIB:esx-base:5.0.0-1.25.912577",
                     "5.1.0", "VIB:esx-base:5.1.0-0.8.911593");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
