# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105086");
  script_cve_id("CVE-2014-0114", "CVE-2013-4590", "CVE-2013-4322", "CVE-2014-0050", "CVE-2013-0242", "CVE-2013-1914");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-27T05:05:08+0000");
  script_name("VMware ESXi product updates to third party libraries (VMSA-2014-0008)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0008.html");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. vCenter Server Apache Struts Update

  The Apache Struts library is updated to address a security issue.
  This issue may lead to remote code execution after authentication.

  b. vCenter Server tc-server 2.9.5 / Apache Tomcat 7.0.52 updates

  tc-server has been updated to version 2.9.5 to address multiple security issues.
  This version of tc-server includes Apache Tomcat 7.0.52.

  c. Update to ESXi glibc package

  glibc is updated to address multiple security issues.

  d. vCenter and Update Manager, Oracle JRE 1.7 Update 55

  Oracle has documented the CVE identifiers that are addressed in JRE 1.7.0
  update 55 in the Oracle Java SE Critical Patch Update Advisory of April 2014");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware has updated vSphere third party libraries.");

  script_tag(name:"affected", value:"VMware ESXi 5.5 without patch ESXi550-201409101-SG.");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-11 11:04:01 +0100 (Thu, 11 Sep 2014)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

patches = make_array("5.5.0", "VIB:esx-base:5.5.0-2.33.2068190",
                     "5.1.0", "VIB:esx-base:5.1.0-2.47.2323231");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
