# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2914.1");
  script_cve_id("CVE-2019-1010180");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-01 15:39:30 +0000 (Thu, 01 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2914-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192914-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/ECO-368");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-November/006096.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the SUSE-SU-2019:2914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdb fixes the following issues:

Update to gdb 8.3.1: (jsc#ECO-368)

Security issues fixed:

- CVE-2019-1010180: Fixed a potential buffer overflow when loading ELF sections larger than the file. (bsc#1142772)

Upgrade libipt from v2.0 to v2.0.1.

- Enable librpm for version > librpm.so.3 [bsc#1145692]:
 * Allow any librpm.so.x
 * Add %build test to check for 'zypper install <rpm-packagename>'
 message

- Copy gdbinit from fedora master @ 25caf28. Add
 gdbinit.without-python, and use it for --without=python.

Rebase to 8.3 release (as in fedora 30 @ 1e222a3).

* DWARF index cache: GDB can now automatically save indices of DWARF
 symbols on disk to speed up further loading of the same binaries.
* Ada task switching is now supported on aarch64-elf targets when
 debugging a program using the Ravenscar Profile.
* Terminal styling is now available for the CLI and the TUI.
* Removed support for old demangling styles arm, edg, gnu, hp and
 lucid.
* Support for new native configuration RISC-V GNU/Linux (riscv*-*-linux*).

- Implemented access to more POWER8 registers. [fate#326120, fate#325178]

- Add gdb-s390-handle-arch13.diff to handle most new s390 arch13 instructions. [fate#327369, jsc#ECO-368]");

  script_tag(name:"affected", value:"'gdb' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~8.3.1~1.12.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~8.3.1~1.12.1", rls:"SLES12.0SP2"))) {
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
