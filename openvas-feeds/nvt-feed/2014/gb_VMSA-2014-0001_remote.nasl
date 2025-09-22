# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103885");
  script_cve_id("CVE-2014-1207", "CVE-2014-1208");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("2025-03-18T05:38:50+0000");
  script_name("VMware ESXi address several security issues (VMSA-2014-0001) - Remote Version Check");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0001.html");

  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-01-20 12:04:01 +0100 (Mon, 20 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_tag(name:"summary", value:"VMware ESXi address several security issues.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. VMware ESXi and ESX NFC NULL pointer dereference

  VMware ESXi and ESX contain a NULL pointer dereference in the handling of the Network File Copy
  (NFC) traffic. To exploit this vulnerability, an attacker must intercept and modify the NFC
  traffic between ESXi/ESX and the client. Exploitation of the issue may lead to a Denial of
  Service.

  To reduce the likelihood of exploitation, vSphere components should be deployed on an isolated
  management network.

  b. VMware VMX process denial of service vulnerability

  Due to a flaw in the handling of invalid ports, it is possible to cause the VMX process to fail.
  This vulnerability may allow a guest user to affect the VMX process resulting in a partial denial
  of service on the host.");

  script_tag(name:"affected", value:"- VMware ESXi 5.1 Build < 1483097

  - VMware ESXi 5.0 Build < 1311177");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

if(!esxBuild = get_kb_item("VMware/ESX/build"))
  exit(0);

fixed_builds = make_array("5.0.0", "1311177",
                          "5.1.0", "1483097");

if(!fixed_builds[esxVersion])
  exit(0);

if(int(esxBuild) < int(fixed_builds[esxVersion])) {
  security_message(port:0, data:esxi_remote_report(ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion]));
  exit(0);
}

exit(99);
