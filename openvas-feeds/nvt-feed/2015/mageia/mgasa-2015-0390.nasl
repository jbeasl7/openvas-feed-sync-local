# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130003");
  script_cve_id("CVE-2015-1333", "CVE-2015-4176", "CVE-2015-4177", "CVE-2015-4178", "CVE-2015-4692", "CVE-2015-4700", "CVE-2015-5697", "CVE-2015-5706", "CVE-2015-5707");
  script_tag(name:"creation_date", value:"2015-10-15 03:54:57 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-06 18:30:11 +0000 (Fri, 06 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0390");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0390.html");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_4.0");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_4.1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16654");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.1");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.2");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.3");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.4");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.5");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.6");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.7");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.1.8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2015-0390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update provides an upgrade to the upstream 4.1 longterm
kernel series, currently based on 4.1.8 and resolves at least the following
security issues:

It was found that the Linux kernel's keyring implementation would leak
memory when adding a key to a keyring via the add_key() function. A
local attacker could use this flaw to exhaust all available memory on
the system. (CVE-2015-1333)

A flaw was found in the Linux kernel where the deletion of a file or
directory could trigger an unmount and reveal data under a mount point.
This flaw was inadvertently introduced with the new feature of being able
to lazily unmount a mount tree when using file system user namespaces.
(CVE-2015-4176)

A flaw was discovered in the kernel's collect_mounts function. If the kernel
audit subsystem called collect_mounts to audit an unmounted path, it could
panic the system. With this flaw, an unprivileged user could call umount
(MNT_DETACH) to launch a denial-of-service attack. (CVE-2015-4177)

A flaw was found in the Linux kernel which is related to the user namespace
lazily unmounting file systems. The fs_pin struct has two members (m_list
and s_list) which are usually initialized on use in the pin_insert_group
function. However, these members might go unmodified, in this case, the
system panics when it attempts to destroy or free them. This flaw could be
used to launch a denial-of-service attack. (CVE-2015-4178)

A DoS flaw was found for a Linux kernel built for the x86 architecture which
had the KVM virtualization support(CONFIG_KVM) enabled. The kernel would be
vulnerable to a NULL pointer dereference flaw in Linux kernel's
kvm_apic_has_events() function while doing an ioctl. An unprivileged user
able to access the '/dev/kvm' device could use this flaw to crash the system
kernel. (CVE-2015-4692)

A flaw was found in the kernel's implementation of the Berkeley Packet
Filter (BPF). A local attacker could craft BPF code to crash the system
by creating a situation in which the JIT compiler would fail to correctly
optimize the JIT image on the last pass. This would lead to the CPU
executing instructions that were not part of the JIT code. (CVE-2015-4700)

The get_bitmap_file function in drivers/md/md.c in the Linux kernel before
4.1.6 does not initialize a certain bitmap data structure, which allows
local users to obtain sensitive information from kernel memory via a
GET_BITMAP_FILE ioctl call. (CVE-2015-5697)

Use-after-free vulnerability in the path_openat function in fs/namei.c in
the Linux kernel 3.x and 4.x before 4.0.4 allows local users to cause a
denial of service or possibly have unspecified other impact via O_TMPFILE
filesystem operations that leverage a duplicate cleanup operation.
(CVE-2015-5706)

It was discovered that an integer overflow error existed in the SCSIgeneric
(sg) driver in the Linux kernel. A local attacker with writepermission to a
SCSI generic device ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.1.8-1.mga5", rpm:"kernel-linus-4.1.8-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.1.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.1.8-1.mga5", rpm:"kernel-linus-devel-4.1.8-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.1.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.1.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.1.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.1.8-1.mga5", rpm:"kernel-linus-source-4.1.8-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.1.8~1.mga5", rls:"MAGEIA5"))) {
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
