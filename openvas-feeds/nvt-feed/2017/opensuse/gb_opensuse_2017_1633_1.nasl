# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851571");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-06-21 19:12:48 +0200 (Wed, 21 Jun 2017)");
  script_cve_id("CVE-2017-1000364", "CVE-2017-1000380", "CVE-2017-7346", "CVE-2017-9242");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-18 10:29:00 +0000 (Thu, 18 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2017:1633-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 42.2 kernel was updated to 4.4.72 to receive various
  security and bugfixes.

  The following security bugs were fixed:

  - CVE-2017-1000364: An issue was discovered in the size of the stack guard
  page on Linux, specifically a 4k stack guard page is not sufficiently
  large and can be 'jumped' over (the stack guard page is bypassed), this
  affects Linux Kernel versions 4.11.5 and earlier (the stackguard page
  was introduced in 2010) (bnc#1039348).

  - CVE-2017-1000380: sound/core/timer.c in the Linux kernel is vulnerable
  to a data race in the ALSA /dev/snd/timer driver resulting in local
  users being able to read information belonging to other users, i.e.,
  uninitialized memory contents may be disclosed when a read and an ioctl
  happen at the same time (bnc#1044125).

  - CVE-2017-7346: The vmw_gb_surface_define_ioctl function in
  drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not
  validate certain levels data, which allowed local users to cause a
  denial of service (system hang) via a crafted ioctl call for a
  /dev/dri/renderD* device (bnc#1031796).

  - CVE-2017-9242: The __ip6_append_data function in net/ipv6/ip6_output.c
  in the Linux kernel is too late in checking whether an overwrite of an
  skb data structure may occur, which allowed local users to cause a
  denial of service (system crash) via crafted system calls (bnc#1041431).

  The following non-security bugs were fixed:

  - ASoC: Intel: Skylake: Uninitialized variable in probe_codec()
  (bsc#1043231).

  - IB/core: Fix kernel crash during fail to initialize device (bsc#1022595
  FATE#322350).

  - IB/core: For multicast functions, verify that LIDs are multicast LIDs
  (bsc#1022595 FATE#322350).

  - IB/core: If the MGID/MLID pair is not on the list return an error
  (bsc#1022595 FATE#322350).

  - IB/ipoib: Fix deadlock between ipoib_stop and mcast join flow
  (bsc#1022595 FATE#322350).

  - Make __xfs_xattr_put_listen preperly report errors (bsc#1041242).

  - NFS: Fix an LOCK/OPEN race when unlinking an open file (git-fixes).

  - NFSv4: Fix the underestimation of delegation XDR space reservation
  (git-fixes).

  - NFSv4: fix a reference leak caused WARNING messages (git-fixes).

  - PM / QoS: Fix memory leak on resume_latency.notifiers (bsc#1043231).

  - SUNRPC: Silence WARN_ON when NFSv4.1 over RDMA is in use (git-fixes).

  - SUNRPC: ensure correct error is reported by xs_tcp_setup_socket()
  (git-fixes).

  - Update patches.fixes/xen-silence-efi-error-messge.patch (bnc#1039900).

  - [media] vb2: Fix an off by one error in 'vb2_plane_vaddr' (bsc#1043231).

  - bcache: fix calling  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"Kernel on openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:1633-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.72~18.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.4.72~18.12.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.4.72~18.12.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-pdf", rpm:"kernel-docs-pdf~4.4.72~18.12.3", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.72~18.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.72~18.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.4.72~18.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.4.72~18.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.72~18.12.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.4.72~18.12.2", rls:"openSUSELeap42.2"))) {
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
