# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105508");
  script_cve_id("CVE-2015-6933");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("2023-07-20T05:05:17+0000");
  script_name("VMware ESXi updates address important guest privilege escalation vulnerability (VMSA-2016-0001)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0001.html");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"Important Windows-based guest privilege escalation in VMware Tools

  A kernel memory corruption vulnerability is present in the VMware Tools 'Shared Folders' (HGFS) feature
  running on Microsoft Windows. Successful exploitation of this issue could lead to an escalation of privilege
  in the guest operating system.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware ESXi updates address important guest privilege escalation vulnerability.");

  script_tag(name:"affected", value:"VMware ESXi 6.0 without patch ESXi600-201512102-SG

  VMware ESXi 5.5 without patch ESXi550-201512102-SG

  VMware ESXi 5.1 without patch ESXi510-201510102-SG

  VMware ESXi 5.0 without patch ESXi500-201510102-SG");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:22:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-14 10:44:54 +0100 (Thu, 14 Jan 2016)");

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

patches = make_array("5.0.0", "VIB:tools-light:5.0.0-3.70.3088986",
                     "5.1.0", "VIB:tools-light:5.1.0-3.57.3021178",
                     "5.5.0", "VIB:tools-light:5.5.0-3.75.3247226",
                     "6.0.0", "VIB:tools-light:6.0.0-1.23.3341439");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
