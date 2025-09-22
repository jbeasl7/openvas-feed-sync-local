# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850801");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1979", "CVE-2014-1739", "CVE-2014-2706", "CVE-2014-3153", "CVE-2014-4027", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-4667", "CVE-2014-4943", "CVE-2014-5077", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 12:17:50 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for Linux (SUSE-SU-2014:1319-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to fix
  various bugs and security issues.

  The following security bugs have been fixed:

  *

  CVE-2014-1739: The media_device_enum_entities function in
  drivers/media/media-device.c in the Linux kernel before 3.14.6 does not
  initialize a certain data structure, which allows local users to
  obtain sensitive information from kernel memory by leveraging
  /dev/media0 read access for a MEDIA_IOC_ENUM_ENTITIES ioctl call
  (bnc#882804).

  *

  CVE-2014-4171: mm/shmem.c in the Linux kernel through 3.15.1 does
  not properly implement the interaction between range notification and hole
  punching, which allows local users to cause a denial of service (i_mutex
  hold) by using the mmap system call to access a hole, as demonstrated by
  interfering with intended shmem activity by blocking completion of (1) an
  MADV_REMOVE madvise call or (2) an FALLOC_FL_PUNCH_HOLE fallocate call
  (bnc#883518).

  *

  CVE-2014-4508: arch/x86/kernel/entry_32.S in the Linux kernel
  through 3.15.1 on 32-bit x86 platforms, when syscall auditing is enabled
  and the sep CPU feature flag is set, allows local users to cause a denial
  of service (OOPS and system crash) via an invalid syscall number, as
  demonstrated by number 1000 (bnc#883724).

  *

  CVE-2014-4667: The sctp_association_free function in
  net/sctp/associola.c in the Linux kernel before 3.15.2 does not properly
  manage a certain backlog value, which allows remote attackers to cause a
  denial of service (socket outage) via a crafted SCTP packet (bnc#885422).

  *

  CVE-2014-4943: The PPPoL2TP feature in net/l2tp/l2tp_ppp.c in the
  Linux kernel through 3.15.6 allows local users to gain privileges by
  leveraging data-structure differences between an l2tp socket and an inet
  socket (bnc#887082).

  *

  CVE-2014-5077: The sctp_assoc_update function in
  net/sctp/associola.c in the Linux kernel through 3.15.8, when SCTP
  authentication is enabled, allows remote attackers to cause a denial of
  service (NULL pointer dereference and OOPS) by starting to establish an
  association between two endpoints immediately after an exchange of INIT
  and INIT ACK chunks to establish an earlier association between these
  endpoints in the opposite direction (bnc#889173).

  *

  CVE-2014-5471: Stack consumption vulnerability in the
  parse_rock_ridge_inode_internal function in fs/isofs/rock.c in the Linux
  kernel through 3.16.1 allows local users to cause a denial of service
  (uncontrolled recursion, and system crash or reboot) via a crafted iso9660
  image with ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"Linux on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1319-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.4_04_3.0.101_0.40~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.4_04_3.0.101_0.40~0.7.3", rls:"SLES11.0SP3"))) {
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
