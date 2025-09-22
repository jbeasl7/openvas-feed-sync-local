# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123513");
  script_cve_id("CVE-2013-4419");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1536)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1536");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1536.html");
  script_xref(name:"URL", value:"https://github.com/libguestfs/libguestfs/branches");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libguestfs' package(s) announced via the ELSA-2013-1536 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:1.20.11-2]
- Fix CVE-2013-4419: insecure temporary directory handling for
 guestfish's network socket
 resolves: rhbz#1019737

[1:1.20.11-1]
- Rebase to libguestfs 1.20.11.
 resolves: rhbz#958183
- Remove buildnet: builds now detect network automatically.
- The rhel-6.x branches containing the patches used in RHEL are
 now stored on a public git repository
 ([link moved to references]).
- Compare spec file to Fedora 18 and fix where necessary.
- Backport new APIs part-get-gpt-type and part-set-gpt-type
 resolves: rhbz#965495
- Fix DoS (abort) due to a double free flaw when inspecting certain guest
 files / images (CVE-2013-2124)
 resolves: rhbz#968337
- libguestfs-devel should depend on an explicit version of
 libguestfs-tools-c, in order that the latest package is pulled in.
- Rebuild against Augeas >= 1.0.0-5
 resolves: rhbz#971207
- Backport Windows inspection changes
 resolves: rhbz#971090
- Add back state test commands to guestfish
 resolves: rhbz#971664
- Work around problem with ntfsresize command in RHEL 6
 resolves: rhbz#971326
- Fix txz-out API
 resolves: rhbz#972413
- Move virt-sysprep to the libguestfs-tools-c package since it's no longer
 a shell script
 resolves: rhbz#975572
- Fix hostname inspection because of faulty Augeas path expression
 resolves: rhbz#975377
- Calculate appliance root correctly when iface drives are added
 resolves: rhbz#975760
- Add notes about resizing Windows disk images to virt-resize documentation
 resolves: rhbz#975753
- Remove dependency on lsscsi, not available in 6Client
 resolves: rhbz#973425
- Fix yum cache copy so it works if there are multiple repos
 resolves: rhbz#980502
- Fix hivex-commit API to fail with relative paths
 resolves: rhbz#980372
- Better documentation for filesystem-available API
 resolves: rhbz#980358
- Fix double free when kernel link fails during launch
 resolves: rhbz#983690
- Fix virt-sysprep --firstboot option
 resolves: rhbz#988863
- Fix cap-get-file so it returns empty string instead of error on no cap
 resolves: rhbz#989352
- Better documentation for acl-set-file
 resolves: rhbz#985269
- Fix bogus waitpid error when using guestfish --remote
 resolves: rhbz#996825
- Disable 9p support
 resolves: rhbz#997884
- Document that guestfish --remote doesn't work with certain other arguments
 resolves: rhbz#996039
- Enable kvmclock in the appliance to reduce clock instability
 resolves: rhbz#998108
- Fix 'sh' command before mount causes daemon to segfault
 resolves: rhbz#1000122
- Various fixes to tar-out 'excludes' (RHBZ#1001875)
- Document use of glob + rsync-out (RHBZ#1001876)
- Document mke2fs blockscount (RHBZ#1002032)");

  script_tag(name:"affected", value:"'libguestfs' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-devel", rpm:"libguestfs-devel~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-java", rpm:"libguestfs-java~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-java-devel", rpm:"libguestfs-java-devel~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-javadoc", rpm:"libguestfs-javadoc~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-libguestfs", rpm:"ocaml-libguestfs~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-libguestfs-devel", rpm:"ocaml-libguestfs-devel~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libguestfs", rpm:"python-libguestfs~1.20.11~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libguestfs", rpm:"ruby-libguestfs~1.20.11~2.el6", rls:"OracleLinux6"))) {
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
