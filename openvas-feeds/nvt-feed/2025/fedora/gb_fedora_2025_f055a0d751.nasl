# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.102055970100751");
  script_cve_id("CVE-2025-23395", "CVE-2025-46802", "CVE-2025-46803");
  script_tag(name:"creation_date", value:"2025-07-21 04:19:44 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-07-21T05:44:15+0000");
  script_tag(name:"last_modification", value:"2025-07-21 05:44:15 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-f055a0d751)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-f055a0d751");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-f055a0d751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2362065");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366507");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367169");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2368500");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2368501");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2368503");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2368504");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2374606");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375347");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'screen' package(s) announced via the FEDORA-2025-f055a0d751 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update default config options for build.

----

New upstream release 5.0.1");

  script_tag(name:"affected", value:"'screen' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"screen", rpm:"screen~5.0.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"screen-debuginfo", rpm:"screen-debuginfo~5.0.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"screen-debugsource", rpm:"screen-debugsource~5.0.1~4.fc42", rls:"FC42"))) {
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
