# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886290");
  script_cve_id("CVE-2022-36763", "CVE-2022-36764", "CVE-2022-36765", "CVE-2023-4522", "CVE-2023-45230", "CVE-2023-45231", "CVE-2023-45232", "CVE-2023-45233", "CVE-2023-45234", "CVE-2023-45235");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:06 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 15:58:27 +0000 (Tue, 23 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-a9dead34c5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a9dead34c5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-a9dead34c5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257587");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257588");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257589");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258679");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258687");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258690");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258693");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258696");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258699");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258701");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the FEDORA-2024-a9dead34c5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to edk2-stable202402");

  script_tag(name:"affected", value:"'edk2' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"edk2", rpm:"edk2~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-aarch64", rpm:"edk2-aarch64~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-arm", rpm:"edk2-arm~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-debugsource", rpm:"edk2-debugsource~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-experimental", rpm:"edk2-experimental~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-ext4", rpm:"edk2-ext4~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-ovmf", rpm:"edk2-ovmf~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-ovmf-ia32", rpm:"edk2-ovmf-ia32~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-ovmf-xen", rpm:"edk2-ovmf-xen~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-riscv64", rpm:"edk2-riscv64~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-tools", rpm:"edk2-tools~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-tools-debuginfo", rpm:"edk2-tools-debuginfo~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-tools-doc", rpm:"edk2-tools-doc~20240214~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"edk2-tools-python", rpm:"edk2-tools-python~20240214~2.fc39", rls:"FC39"))) {
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
