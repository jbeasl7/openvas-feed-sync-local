# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885582");
  script_cve_id("CVE-2023-39325");
  script_tag(name:"creation_date", value:"2024-01-20 02:02:12 +0000 (Sat, 20 Jan 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-31 18:05:45 +0000 (Tue, 31 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-07c811c7a5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-07c811c7a5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-07c811c7a5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248209");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248294");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-facebook-time' package(s) announced via the FEDORA-2024-07c811c7a5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-39325");

  script_tag(name:"affected", value:"'golang-github-facebook-time' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"calnex", rpm:"calnex~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calnex-debuginfo", rpm:"calnex-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-facebook-time", rpm:"golang-github-facebook-time~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-facebook-time-debugsource", rpm:"golang-github-facebook-time-debugsource~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-facebook-time-devel", rpm:"golang-github-facebook-time-devel~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpcheck", rpm:"ntpcheck~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpcheck-debuginfo", rpm:"ntpcheck-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpresponder", rpm:"ntpresponder~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpresponder-debuginfo", rpm:"ntpresponder-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pshark", rpm:"pshark~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pshark-debuginfo", rpm:"pshark-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptp4u", rpm:"ptp4u~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptp4u-debuginfo", rpm:"ptp4u-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptpcheck", rpm:"ptpcheck~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptpcheck-debuginfo", rpm:"ptpcheck-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sptp", rpm:"sptp~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sptp-debuginfo", rpm:"sptp-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ziffy", rpm:"ziffy~0^20240110git1649917~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ziffy-debuginfo", rpm:"ziffy-debuginfo~0^20240110git1649917~1.fc39", rls:"FC39"))) {
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
