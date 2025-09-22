# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.9873101441021019100");
  script_cve_id("CVE-2024-1543", "CVE-2024-1545");
  script_tag(name:"creation_date", value:"2024-09-12 04:13:08 +0000 (Thu, 12 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:27:08 +0000 (Wed, 04 Sep 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-b73e44fe9d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b73e44fe9d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b73e44fe9d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2308628");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2308629");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2308630");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2308631");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wolfssl' package(s) announced via the FEDORA-2024-b73e44fe9d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RHBZ#2308628 RHBZ#2308629 RHBZ#2308630 RHBZ#2308631 fixed in 5.7.2 release");

  script_tag(name:"affected", value:"'wolfssl' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"wolfssl", rpm:"wolfssl~5.7.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wolfssl-debuginfo", rpm:"wolfssl-debuginfo~5.7.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wolfssl-debugsource", rpm:"wolfssl-debugsource~5.7.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wolfssl-devel", rpm:"wolfssl-devel~5.7.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wolfssl-doc", rpm:"wolfssl-doc~5.7.2~2.fc39", rls:"FC39"))) {
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
