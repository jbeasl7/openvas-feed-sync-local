# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1040.1");
  script_cve_id("CVE-2026-29111", "CVE-2026-4105");
  script_tag(name:"creation_date", value:"2026-03-30 04:57:45 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-13 19:55:13 +0000 (Fri, 13 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1040-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261040-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259697");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024932.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2026:1040-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

- CVE-2026-4105: privilege escalation due to improper access control in RegisterMachine D-Bus method (bsc#1259650).
- CVE-2026-29111: local unprivileged user can trigger an assert in systemd (bsc#1259418).
- udev: check for invalid chars in various fields received from the kernel (bsc#1259697).

Changelog:

- a943e3ce2f machined: reject invalid class types when registering machines
- 71593f77db udev: fix review mixup
- 73a89810b4 udev-builtin-net-id: print cescaped bad attributes
- 0f360bfdc0 udev-builtin-net_id: do not assume the current interface name is ethX
- 40905232e2 udev: ensure tag parsing stays within bounds
- 7bce9026e3 udev: ensure there is space for trailing NUL before calling sprintf
- d018ac1ea3 udev: check for invalid chars in various fields received from the kernel
- aef6e11921 core/cgroup: avoid one unnecessary strjoina()
- cc7426f38a sd-json: fix off-by-one issue when updating parent for array elements
- 26a748f727 core: validate input cgroup path more prudently
- 99d8308fde core/dbus-manager: propagate meaningful dbus errors from EnqueueMarkedJobs");

  script_tag(name:"affected", value:"'systemd' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-boot", rpm:"systemd-boot~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump", rpm:"systemd-coredump~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-doc", rpm:"systemd-doc~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-experimental", rpm:"systemd-experimental~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-homed", rpm:"systemd-homed~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-remote", rpm:"systemd-journal-remote~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-lang", rpm:"systemd-lang~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-network", rpm:"systemd-network~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd", rpm:"systemd-networkd~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-portable", rpm:"systemd-portable~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved", rpm:"systemd-resolved~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvcompat", rpm:"systemd-sysvcompat~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-testsuite", rpm:"systemd-testsuite~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~254.27~150600.4.62.1", rls:"openSUSELeap15.6"))) {
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
