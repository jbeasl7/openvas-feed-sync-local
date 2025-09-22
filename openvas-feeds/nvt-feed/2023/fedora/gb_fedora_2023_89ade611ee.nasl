# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885179");
  script_cve_id("CVE-2022-48064", "CVE-2022-48065");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:21 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-26 02:15:21 +0000 (Sat, 26 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-89ade611ee)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-89ade611ee");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-89ade611ee");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2233958");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2233961");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2233965");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the FEDORA-2023-89ade611ee advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport upstream commit d28fbc7197b which fixes RHBZ 2233965, Security fix for CVE-2022-48065

----

Security fix for CVE-2022-48064, Backport upstream commit 8f2c64de86b which fixes RHBZ 2233961,");

  script_tag(name:"affected", value:"'gdb' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~13.2~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debuginfo", rpm:"gdb-debuginfo~13.2~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debugsource", rpm:"gdb-debugsource~13.2~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-doc", rpm:"gdb-doc~13.2~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-gdbserver", rpm:"gdb-gdbserver~13.2~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-headless", rpm:"gdb-headless~13.2~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-minimal", rpm:"gdb-minimal~13.2~10.fc39", rls:"FC39"))) {
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
