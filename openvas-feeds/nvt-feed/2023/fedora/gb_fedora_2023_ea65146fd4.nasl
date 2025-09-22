# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885162");
  script_cve_id("CVE-2023-22338", "CVE-2023-22840");
  script_tag(name:"creation_date", value:"2023-11-05 02:21:15 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-18 18:46:20 +0000 (Fri, 18 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-ea65146fd4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-ea65146fd4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-ea65146fd4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171625");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2185325");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231401");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2235293");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oneVPL, oneVPL-intel-gpu' package(s) announced via the FEDORA-2023-ea65146fd4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update oneVPL and oneVPL-intel-gpu to latest releases. Fixes CVE-2023-22338 and CVE-2023-22840. No ABI changes.");

  script_tag(name:"affected", value:"'oneVPL, oneVPL-intel-gpu' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"oneVPL", rpm:"oneVPL~2023.3.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-debuginfo", rpm:"oneVPL-debuginfo~2023.3.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-debugsource", rpm:"oneVPL-debugsource~2023.3.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-devel", rpm:"oneVPL-devel~2023.3.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-intel-gpu", rpm:"oneVPL-intel-gpu~23.3.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-intel-gpu-debuginfo", rpm:"oneVPL-intel-gpu-debuginfo~23.3.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-intel-gpu-debugsource", rpm:"oneVPL-intel-gpu-debugsource~23.3.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-intel-gpu-devel", rpm:"oneVPL-intel-gpu-devel~23.3.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-samples", rpm:"oneVPL-samples~2023.3.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oneVPL-samples-debuginfo", rpm:"oneVPL-samples-debuginfo~2023.3.1~1.fc39", rls:"FC39"))) {
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
