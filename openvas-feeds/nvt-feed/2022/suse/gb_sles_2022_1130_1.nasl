# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1130.1");
  script_tag(name:"creation_date", value:"2022-04-11 13:40:56 +0000 (Mon, 11 Apr 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1130-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1130-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221130-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197134");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-April/010669.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsolv, libzypp, zypper' package(s) announced via the SUSE-SU-2022:1130-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsolv, libzypp, zypper fixes the following issues:

Security relevant fix:

- Harden package signature checks (bsc#1184501).

libsolv to 0.7.22:

- reworked choice rule generation to cover more usecases
- support SOLVABLE_PREREQ_IGNOREINST in the ordering code (bsc#1196514)
- support parsing of Debian's Multi-Arch indicator

- fix segfault on conflict resolution when using bindings
- fix split provides not working if the update includes a forbidden vendor change
- support strict repository priorities
 new solver flag: SOLVER_FLAG_STRICT_REPO_PRIORITY
- support zstd compressed control files in debian packages
- add an ifdef allowing to rename Solvable dependency members
 ('requires' is a keyword in C++20)
- support setting/reading userdata in solv files
 new functions: repowriter_set_userdata, solv_read_userdata
- support queying of the custom vendor check function
 new function: pool_get_custom_vendorcheck
- support solv files with an idarray block
- allow accessing the toolversion at runtime

libzypp to 17.30.0:

- ZConfig: Update solver settings if target changes (bsc#1196368)
- Fix possible hang in singletrans mode (bsc#1197134)
- Do 2 retries if mount is still busy.
- Fix package signature check (bsc#1184501)
 Pay attention that header and payload are secured by a valid
 signature and report more detailed which signature is missing.
- Retry umount if device is busy (bsc#1196061, closes #381)
 A previously released ISO image may need a bit more time to
 release it's loop device. So we wait a bit and retry.
- Fix serializing/deserializing type mismatch in zypp-rpm protocol (bsc#1196925)
- Fix handling of ISO media in releaseAll (bsc#1196061)
- Hint on common ptf resolver conflicts (bsc#1194848)
- Hint on ptf<>patch resolver conflicts (bsc#1194848)

zypper to 1.14.52:

- info: print the packages upstream URL if available (fixes #426)
- info: Fix SEGV with not installed PTFs (bsc#1196317)
- Don't prevent less restrictive umasks (bsc#1195999)");

  script_tag(name:"affected", value:"'libsolv, libzypp, zypper' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel", rpm:"libsolv-devel~0.7.22~150000.3.51.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.7.22~150000.3.51.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~17.30.0~150000.3.95.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~17.30.0~150000.3.95.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.7.22~150000.3.51.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.7.22~150000.3.51.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv", rpm:"python3-solv~0.7.22~150000.3.51.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv", rpm:"ruby-solv~0.7.22~150000.3.51.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.14.52~150000.3.69.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.14.52~150000.3.69.2", rls:"SLES15.0"))) {
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
