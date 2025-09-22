# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01889.1");
  script_cve_id("CVE-2025-47711", "CVE-2025-47712");
  script_tag(name:"creation_date", value:"2025-06-13 04:10:49 +0000 (Fri, 13 Jun 2025)");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 01:19:08 +0000 (Thu, 21 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01889-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01889-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501889-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243110");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040220.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nbdkit' package(s) announced via the SUSE-SU-2025:01889-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-47712: integer overflow in blocksize filter when processing client block status requests larger than 2**32
 will trigger an assertion failure and cause a denial-of-service. (bsc#1243108).
- CVE-2025-47711: off-by-one error when processing block status results from plugins on behalf of an NBD client may
 trigger an assertion failure and cause a denial of service (bsc#1243110).

Other fixes and changes:

- tests: Add test-blkio.sh to unconditional EXTRA_DIST rule.
- Revert 'valgrind: Add suppression for liblzma bug'.
- vddk: Move 'Unknown error' information to the manual.
- ocaml Add better comments to the example plugin.
- ocaml: Simplify pread operation.
- ocaml: Define a struct handle to hold the OCaml handle.
- ocaml: Add OCaml version to --dump-plugin output.
- ocaml: Print callback name when an exception is printed.
- ocaml: Combine all exception printing into a single macro.");

  script_tag(name:"affected", value:"'nbdkit' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"nbdkit", rpm:"nbdkit~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-bash-completion", rpm:"nbdkit-bash-completion~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-basic-filters", rpm:"nbdkit-basic-filters~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-basic-plugins", rpm:"nbdkit-basic-plugins~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-curl-plugin", rpm:"nbdkit-curl-plugin~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-devel", rpm:"nbdkit-devel~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-example-plugins", rpm:"nbdkit-example-plugins~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-gzip-filter", rpm:"nbdkit-gzip-filter~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-linuxdisk-plugin", rpm:"nbdkit-linuxdisk-plugin~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-nbd-plugin", rpm:"nbdkit-nbd-plugin~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-python-plugin", rpm:"nbdkit-python-plugin~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-server", rpm:"nbdkit-server~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ssh-plugin", rpm:"nbdkit-ssh-plugin~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tar-filter", rpm:"nbdkit-tar-filter~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tmpdisk-plugin", rpm:"nbdkit-tmpdisk-plugin~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-vddk-plugin", rpm:"nbdkit-vddk-plugin~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-xz-filter", rpm:"nbdkit-xz-filter~1.36.5~150400.3.9.1", rls:"openSUSELeap15.6"))) {
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
