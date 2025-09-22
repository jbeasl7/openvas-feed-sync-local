# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.97510073970399");
  script_cve_id("CVE-2024-38822", "CVE-2024-38823", "CVE-2024-38824", "CVE-2024-38825", "CVE-2025-22236", "CVE-2025-22237", "CVE-2025-22238", "CVE-2025-22239", "CVE-2025-22240", "CVE-2025-22241", "CVE-2025-22242");
  script_tag(name:"creation_date", value:"2025-06-30 04:13:11 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-10 00:34:26 +0000 (Thu, 10 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-a5d73a0399)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a5d73a0399");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a5d73a0399");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372747");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372755");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372756");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372757");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372758");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372772");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372773");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372775");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the FEDORA-2025-a5d73a0399 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Resolves CVE-2024-38824 RHBZ#2372731
- Resolves CVE-2024-38824 RHBZ#2372733
- Resolves CVE-2025-22239 RHBZ#2372732
- Resolves CVE-2025-22239 RHBZ#2372734
- Resolves CVE-2025-22236 RHBZ#2372774
- Resolves CVE-2025-22236 RHBZ#2372776
- Resolves CVE-2025-22242 RHBZ#2372741
- Resolves CVE-2025-22242 RHBZ#2372745
- Resolves CVE-2025-22240 RHBZ#2372746
- Resolves CVE-2025-22241 RHBZ#2372748
- Resolves CVE-2025-22240 RHBZ#2372752
- Resolves CVE-2025-22241 RHBZ#2372753


----

- Resolves RHBZ#2366381
- Resolves CVE-2024-38824 RHBZ#2372731
- Resolves CVE-2024-38824 RHBZ#2372733
- Resolves CVE-2025-22239 RHBZ#2372732
- Resolves CVE-2025-22239 RHBZ#2372734
- Resolves CVE-2025-22236 RHBZ#2372774
- Resolves CVE-2025-22236 RHBZ#2372776
- Resolves CVE-2025-22242 RHBZ#2372741
- Resolves CVE-2025-22242 RHBZ#2372745
- Resolves CVE-2025-22240 RHBZ#2372746
- Resolves CVE-2025-22241 RHBZ#2372748
- Resolves CVE-2025-22240 RHBZ#2372752
- Resolves CVE-2025-22241 RHBZ#2372753");

  script_tag(name:"affected", value:"'salt' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3007.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3007.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3007.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3007.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3007.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3007.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3007.4~4.fc42", rls:"FC42"))) {
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
