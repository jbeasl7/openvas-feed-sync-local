# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884783");
  script_cve_id("CVE-2021-41803", "CVE-2022-3064", "CVE-2022-40716", "CVE-2023-0845", "CVE-2023-25173", "CVE-2023-26054", "CVE-2023-28840", "CVE-2023-28841", "CVE-2023-28842");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:09 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-14 15:23:18 +0000 (Fri, 14 Apr 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-b9c1d0e4c5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b9c1d0e4c5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-b9c1d0e4c5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2156860");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2156864");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163037");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163550");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2174485");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2174544");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2176447");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2176448");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177595");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177596");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184683");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184684");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184685");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184686");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184688");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184689");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2189788");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2189789");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2190033");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moby-engine' package(s) announced via the FEDORA-2023-b9c1d0e4c5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update moby-engine to 24.0.5
- Security fix for CVE-2021-41803
- Security fix for CVE-2023-28842
- Security fix for CVE-2023-28841
- Security fix for CVE-2023-28840
- Security fix for CVE-2023-0845
- Security fix for CVE-2023-26054
- Security fix for CVE-2022-3064
- Security fix for CVE-2022-40716
- Security fix for CVE-2023-25173");

  script_tag(name:"affected", value:"'moby-engine' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"moby-engine", rpm:"moby-engine~24.0.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"moby-engine-debuginfo", rpm:"moby-engine-debuginfo~24.0.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"moby-engine-debugsource", rpm:"moby-engine-debugsource~24.0.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"moby-engine-fish-completion", rpm:"moby-engine-fish-completion~24.0.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"moby-engine-nano", rpm:"moby-engine-nano~24.0.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"moby-engine-zsh-completion", rpm:"moby-engine-zsh-completion~24.0.5~1.fc39", rls:"FC39"))) {
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
