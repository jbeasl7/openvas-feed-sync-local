# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840519");
  script_cve_id("CVE-2010-2237", "CVE-2010-2238", "CVE-2010-2239", "CVE-2010-2242");
  script_tag(name:"creation_date", value:"2010-10-22 14:42:09 +0000 (Fri, 22 Oct 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1008-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1008-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1008-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/655392");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtinst' package(s) announced via the USN-1008-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Libvirt in Ubuntu 10.04 LTS now no longer probes qemu disks for the image
format and defaults to 'raw' when the format is not specified in the XML.
This change in behavior breaks virt-install --import because virtinst in
Ubuntu 10.04 LTS did not allow for specifying a disk format and does not
specify a format in the XML. This update adds the 'format=' option when
specifying a disk. For example, to import an existing VM which uses a qcow2
disk format, use something like the following:

 virt-install --connect=qemu:///session --name test-import --ram=256 \
 --disk path=<path to qcow2 image>,format=qcow2 --import

For more information, see man 1 virt-install.

Original advisory details:

 It was discovered that libvirt would probe disk backing stores without
 consulting the defined format for the disk. A privileged attacker in the
 guest could exploit this to read arbitrary files on the host. This issue
 only affected Ubuntu 10.04 LTS. By default, guests are confined by an
 AppArmor profile which provided partial protection against this flaw.
 (CVE-2010-2237, CVE-2010-2238)

 It was discovered that libvirt would create new VMs without setting a
 backing store format. A privileged attacker in the guest could exploit this
 to read arbitrary files on the host. This issue did not affect Ubuntu 8.04
 LTS. In Ubuntu 9.10 and later guests are confined by an AppArmor profile
 which provided partial protection against this flaw. (CVE-2010-2239)

 Jeremy Nickurak discovered that libvirt created iptables rules with too
 lenient mappings of source ports. A privileged attacker in the guest could
 bypass intended restrictions to access privileged resources on the host.
 (CVE-2010-2242)");

  script_tag(name:"affected", value:"'virtinst' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"virtinst", ver:"0.500.1-2ubuntu6.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
