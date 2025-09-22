# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122806");
  script_cve_id("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-7613", "CVE-2015-7872", "CVE-2015-8104");
  script_tag(name:"creation_date", value:"2015-12-16 09:36:47 +0000 (Wed, 16 Dec 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-2636)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2636");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2636.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-2636 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-573.12.1]
- Revert: [netdrv] igb: add support for 1512 PHY (Stefan Assmann) [1278275 1238551]

[2.6.32-573.11.1]
- [kvm] svm: unconditionally intercept DB (Paolo Bonzini) [1279467 1279468] {CVE-2015-8104}
- [x86] virt: guest to host DoS by triggering an infinite loop in microcode (Paolo Bonzini) [1277557 1277559] {CVE-2015-5307}

[2.6.32-573.10.1]
- [sound] Fix USB audio issues (wrong URB_ISO_ASAP semantics) (Jaroslav Kysela) [1273916 1255071]
- [security] keys: Don't permit request_key() to construct a new keyring (David Howells) [1275927 1273463] {CVE-2015-7872}
- [security] keys: Fix crash when attempt to garbage collect an uninstantiated keyring (David Howells) [1275927 1273463] {CVE-2015-7872}
- [security] keys: Fix race between key destruction and finding a keyring by name (David Howells) [1275927 1273463] {CVE-2015-7872}
- [ipc] Initialize msg/shm IPC objects before doing ipc_addid() (Stanislav Kozina) [1271504 1271505] {CVE-2015-7613}
- [fs] vfs: Test for and handle paths that are unreachable from their mnt_root (Eric W. Biederman) [1209368 1209369] {CVE-2015-2925}
- [fs] dcache: Handle escaped paths in prepend_path (Eric W. Biederman) [1209368 1209369] {CVE-2015-2925}
- [netdrv] igb: add support for 1512 PHY (Stefan Assmann) [1278275 1238551]
- [hid] fix unused rsize usage (Don Zickus) [1268203 1256568]
- [hid] fix data access in implement() (Don Zickus) [1268203 1256568]
- [fs] NFS: Hold i_lock in nfs_wb_page_cancel() while locking a request (Benjamin Coddington) [1273721 1135601]

[2.6.32-573.9.1]
- [mm] hugetlb: fix race in region tracking (Herton R. Krzesinski) [1274599 1260755]
- [mm] hugetlb: improve, cleanup resv_map parameters (Herton R. Krzesinski) [1274599 1260755]
- [mm] hugetlb: unify region structure handling (Herton R. Krzesinski) [1274599 1260755]
- [mm] hugetlb: change variable name reservations to resv (Herton R. Krzesinski) [1274599 1260755]
- [fs] dcache: Log ELOOP rather than creating a loop (Benjamin Coddington) [1272858 1254020]
- [fs] dcache: Fix loop checks in d_materialise_unique (Benjamin Coddington) [1272858 1254020]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.12.1.el6", rls:"OracleLinux6"))) {
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
