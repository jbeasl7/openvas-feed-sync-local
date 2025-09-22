# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.989902101993210298");
  script_cve_id("CVE-2025-47711", "CVE-2025-47712");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 01:19:08 +0000 (Thu, 21 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-bc02ec32fb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-bc02ec32fb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-bc02ec32fb");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2365691");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2365726");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nbdkit' package(s) announced via the FEDORA-2025-bc02ec32fb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream stable branch version 1.40.6");

  script_tag(name:"affected", value:"'nbdkit' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"mingw32-nbdkit", rpm:"mingw32-nbdkit~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-nbdkit-debuginfo", rpm:"mingw32-nbdkit-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-nbdkit", rpm:"mingw64-nbdkit~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-nbdkit-debuginfo", rpm:"mingw64-nbdkit-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit", rpm:"nbdkit~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-S3-plugin", rpm:"nbdkit-S3-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-bash-completion", rpm:"nbdkit-bash-completion~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-basic-filters", rpm:"nbdkit-basic-filters~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-basic-filters-debuginfo", rpm:"nbdkit-basic-filters-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-basic-plugins", rpm:"nbdkit-basic-plugins~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-basic-plugins-debuginfo", rpm:"nbdkit-basic-plugins-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-blkio-plugin", rpm:"nbdkit-blkio-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-blkio-plugin-debuginfo", rpm:"nbdkit-blkio-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-bzip2-filter", rpm:"nbdkit-bzip2-filter~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-bzip2-filter-debuginfo", rpm:"nbdkit-bzip2-filter-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-cc-plugin", rpm:"nbdkit-cc-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-cc-plugin-debuginfo", rpm:"nbdkit-cc-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-cdi-plugin", rpm:"nbdkit-cdi-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-cdi-plugin-debuginfo", rpm:"nbdkit-cdi-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-curl-plugin", rpm:"nbdkit-curl-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-curl-plugin-debuginfo", rpm:"nbdkit-curl-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-debuginfo", rpm:"nbdkit-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-debugsource", rpm:"nbdkit-debugsource~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-devel", rpm:"nbdkit-devel~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-example-plugins", rpm:"nbdkit-example-plugins~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-example-plugins-debuginfo", rpm:"nbdkit-example-plugins-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ext2-filter", rpm:"nbdkit-ext2-filter~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ext2-filter-debuginfo", rpm:"nbdkit-ext2-filter-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-gcs-plugin", rpm:"nbdkit-gcs-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-guestfs-plugin", rpm:"nbdkit-guestfs-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-guestfs-plugin-debuginfo", rpm:"nbdkit-guestfs-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-iso-plugin", rpm:"nbdkit-iso-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-iso-plugin-debuginfo", rpm:"nbdkit-iso-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-libvirt-plugin", rpm:"nbdkit-libvirt-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-libvirt-plugin-debuginfo", rpm:"nbdkit-libvirt-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-linuxdisk-plugin", rpm:"nbdkit-linuxdisk-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-linuxdisk-plugin-debuginfo", rpm:"nbdkit-linuxdisk-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-lua-plugin", rpm:"nbdkit-lua-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-lua-plugin-debuginfo", rpm:"nbdkit-lua-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-nbd-plugin", rpm:"nbdkit-nbd-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-nbd-plugin-debuginfo", rpm:"nbdkit-nbd-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ocaml-plugin", rpm:"nbdkit-ocaml-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ocaml-plugin-debuginfo", rpm:"nbdkit-ocaml-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ocaml-plugin-devel", rpm:"nbdkit-ocaml-plugin-devel~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-perl-plugin", rpm:"nbdkit-perl-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-perl-plugin-debuginfo", rpm:"nbdkit-perl-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-python-plugin", rpm:"nbdkit-python-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-python-plugin-debuginfo", rpm:"nbdkit-python-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-selinux", rpm:"nbdkit-selinux~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-server", rpm:"nbdkit-server~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-server-debuginfo", rpm:"nbdkit-server-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-srpm-macros", rpm:"nbdkit-srpm-macros~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ssh-plugin", rpm:"nbdkit-ssh-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-ssh-plugin-debuginfo", rpm:"nbdkit-ssh-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-stats-filter", rpm:"nbdkit-stats-filter~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-stats-filter-debuginfo", rpm:"nbdkit-stats-filter-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tar-filter", rpm:"nbdkit-tar-filter~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tar-filter-debuginfo", rpm:"nbdkit-tar-filter-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tcl-plugin", rpm:"nbdkit-tcl-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tcl-plugin-debuginfo", rpm:"nbdkit-tcl-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tmpdisk-plugin", rpm:"nbdkit-tmpdisk-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-tmpdisk-plugin-debuginfo", rpm:"nbdkit-tmpdisk-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-torrent-plugin", rpm:"nbdkit-torrent-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-torrent-plugin-debuginfo", rpm:"nbdkit-torrent-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-vddk-plugin", rpm:"nbdkit-vddk-plugin~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-vddk-plugin-debuginfo", rpm:"nbdkit-vddk-plugin-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-xz-filter", rpm:"nbdkit-xz-filter~1.40.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdkit-xz-filter-debuginfo", rpm:"nbdkit-xz-filter-debuginfo~1.40.6~1.fc41", rls:"FC41"))) {
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
