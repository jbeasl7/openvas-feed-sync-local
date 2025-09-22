# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103456");
  script_cve_id("CVE-2010-4295", "CVE-2010-4296", "CVE-2010-4297", "CVE-2010-4294");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");
  script_name("VMware ESXi/ESX patches resolve multiple security issues (VMSA-2010-0018)");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-16 12:42:13 +0100 (Fri, 16 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0018.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2010-0018.");

  script_tag(name:"affected", value:"ESXi 4.1 without patch ESXi410-201010402-BG or later

  ESXi 4.0 without patch ESXi400-201009402-BG or later

  ESXi 3.5 without patch ESXe350-201008402-T-BG or later

  ESX 4.1 without patch ESX410-201010405-BG

  ESX 4.0 without patch ESX400-201009401-SG

  ESX 3.5 without patch ESX350-201008409-BG");

  script_tag(name:"impact", value:"c. OS Command Injection in VMware Tools update

  The issue could allow a user on the host to execute commands on the guest operating system with root privileges.

  The issue can only be exploited if VMware Tools is not fully up-to-date. Windows-based virtual machines are not
  affected.

  d. VMware VMnc Codec frame decompression remote code execution

  An attacker can utilize this to miscalculate a destination pointer, leading to the corruption of a heap buffer,
  and could allow for execution of arbitrary code with the privileges of the user running an application utilizing
  the vulnerable codec.

  For an attack to be successful the user must be tricked into visiting a malicious web page or opening a malicious video
  file on a system that has the vulnerable version of the VMnc codec installed.");

  script_tag(name:"insight", value:"VMware hosted products and ESX patches resolve multiple security issues:

  a. VMware Workstation, Player and Fusion vmware-mount race condition

  The way temporary files are handled by the mounting process could result in a race condition. This
  issue could allow a local user on the host to elevate their privileges.

  VMware Workstation and Player running on Microsoft Windows are not affected.

  b. VMware Workstation, Player and Fusion vmware-mount privilege escalation vmware-mount which is a suid
  binary has a flaw in the way libraries are loaded. This issue could allow local users on the host to
  execute arbitrary shared object files with root privileges.

  VMware Workstation and Player running on Microsoft Windows are not affected.

  c. OS Command Injection in VMware Tools update

  A vulnerability in the input validation of VMware Tools update allows for injection of commands.

  d. VMware VMnc Codec frame decompression remote code execution

  The VMware movie decoder contains the VMnc media codec that is required to play back movies recorded with VMware
  Workstation, VMware Player and VMware ACE, in any compatible media player. The movie decoder is installed as part
  of VMware Workstation, VMware Player and VMware ACE, or can be downloaded as a stand alone package.

  A function in the decoder frame decompression routine implicitly trusts a size value.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("vmware_esx.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

patches = make_array("4.1.0", "ESXi410-201010402-BG",
                     "4.0.0", "ESXi400-201009402-BG");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
