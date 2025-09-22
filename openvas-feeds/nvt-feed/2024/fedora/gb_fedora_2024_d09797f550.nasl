# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886738");
  script_cve_id("CVE-2023-4692", "CVE-2023-4693");
  script_tag(name:"creation_date", value:"2024-05-27 10:45:55 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 19:03:42 +0000 (Wed, 01 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-d09797f550)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-d09797f550");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-d09797f550");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236613");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238343");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241976");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241978");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254370");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the FEDORA-2024-d09797f550 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-4692

Security fix for CVE-2023-4693

Fri Apr 12 2024 Nicolas Frayer <nfrayer@redhat.com> - 2.06-120

- fs/xfs: Handle non-continuous data blocks in directory extents
- Related: #2254370

Fri Mar 08 2024 Nicolas Frayer <nfrayer@redhat.com> - 2.06-119

- GRUB2 NTFS driver vulnerabilities
- (CVE-2023-4692)
- (CVE-2023-4693)
- Resolves: #2236613
- Resolves: #2241978
- Resolves: #2241976
- Resolves: #2238343");

  script_tag(name:"affected", value:"'grub2' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-debuginfo", rpm:"grub2-debuginfo~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-debugsource", rpm:"grub2-debugsource~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64", rpm:"grub2-efi-aa64~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64-cdboot", rpm:"grub2-efi-aa64-cdboot~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64-modules", rpm:"grub2-efi-aa64-modules~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-ia32", rpm:"grub2-efi-ia32~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-ia32-cdboot", rpm:"grub2-efi-ia32-cdboot~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-ia32-modules", rpm:"grub2-efi-ia32-modules~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64", rpm:"grub2-efi-x64~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-cdboot", rpm:"grub2-efi-x64-cdboot~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-modules", rpm:"grub2-efi-x64-modules~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-emu", rpm:"grub2-emu~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-emu-debuginfo", rpm:"grub2-emu-debuginfo~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-emu-modules", rpm:"grub2-emu-modules~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc", rpm:"grub2-pc~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc-modules", rpm:"grub2-pc-modules~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-ppc64le", rpm:"grub2-ppc64le~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-ppc64le-modules", rpm:"grub2-ppc64le-modules~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-debuginfo", rpm:"grub2-tools-debuginfo~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-efi", rpm:"grub2-tools-efi~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-efi-debuginfo", rpm:"grub2-tools-efi-debuginfo~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra-debuginfo", rpm:"grub2-tools-extra-debuginfo~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.06~120.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal-debuginfo", rpm:"grub2-tools-minimal-debuginfo~2.06~120.fc39", rls:"FC39"))) {
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
