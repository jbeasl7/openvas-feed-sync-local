# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105892");
  script_cve_id("CVE-2016-7081", "CVE-2016-7082", "CVE-2016-7083", "CVE-2016-7084", "CVE-2016-7079", "CVE-2016-7080", "CVE-2016-7085", "CVE-2016-7086");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-20T05:05:17+0000");
  script_name("VMware ESXi updates address multiple security issues (VMSA-2016-0014)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0014.html");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The graphic acceleration functions used in VMware Tools for OSX handle memory incorrectly.");

  script_tag(name:"insight", value:"Two resulting NULL pointer dereference vulnerabilities may allow for local privilege escalation
  on Virtual Machines that run OSX.

  The issues can be remediated by installing a fixed version of VMware Tools on affected OSX VMs directly. Alternatively the fixed
  version of Tools can be installed through ESXi or Fusion after first updating to a version of ESXi or Fusion that ships with a
  fixed version of VMware Tools.");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-09-16 11:58:28 +0200 (Fri, 16 Sep 2016)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

patches = make_array("6.0.0", "VIB:tools-light:6.0.0-2.43.4192238",
                     "5.5.0", "VIB:tools-light:5.5.0-3.86.4179631");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
