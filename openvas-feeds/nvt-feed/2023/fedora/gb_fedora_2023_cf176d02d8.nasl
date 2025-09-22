# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884842");
  script_cve_id("CVE-2022-46146");
  script_tag(name:"creation_date", value:"2023-09-22 01:15:53 +0000 (Fri, 22 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 16:09:51 +0000 (Fri, 02 Dec 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-cf176d02d8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-cf176d02d8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-cf176d02d8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2016209");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2149436");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2149440");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171533");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225870");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-exporter-toolkit, golang-github-xhit-str2duration, golang-gopkg-alecthomas-kingpin-2' package(s) announced via the FEDORA-2023-cf176d02d8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2022-46146, update to v0.10.0");

  script_tag(name:"affected", value:"'golang-github-prometheus-exporter-toolkit, golang-github-xhit-str2duration, golang-gopkg-alecthomas-kingpin-2' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-alecthomas-kingpin-2-devel", rpm:"compat-golang-github-alecthomas-kingpin-2-devel~2.3.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-xhit-str2duration-2-devel", rpm:"compat-golang-github-xhit-str2duration-2-devel~2.1.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-exporter-toolkit", rpm:"golang-github-prometheus-exporter-toolkit~0.10.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-exporter-toolkit-devel", rpm:"golang-github-prometheus-exporter-toolkit-devel~0.10.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-xhit-str2duration", rpm:"golang-github-xhit-str2duration~2.1.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-xhit-str2duration-devel", rpm:"golang-github-xhit-str2duration-devel~2.1.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-gopkg-alecthomas-kingpin-2", rpm:"golang-gopkg-alecthomas-kingpin-2~2.3.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-gopkg-alecthomas-kingpin-2-devel", rpm:"golang-gopkg-alecthomas-kingpin-2-devel~2.3.2~1.fc39", rls:"FC39"))) {
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
