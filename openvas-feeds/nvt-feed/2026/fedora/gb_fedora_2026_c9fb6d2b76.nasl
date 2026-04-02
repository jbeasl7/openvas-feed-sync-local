# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.99910298610029876");
  script_cve_id("CVE-2025-47906", "CVE-2025-47910", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2026-03-09 04:44:32 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-c9fb6d2b76)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-c9fb6d2b76");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-c9fb6d2b76");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398776");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399447");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407977");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408652");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409447");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410398");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411298");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412781");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'prometheus' package(s) announced via the FEDORA-2026-c9fb6d2b76 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rename from `golang-github-prometheus` and upgrade to 3.10.0");

  script_tag(name:"affected", value:"'prometheus' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"prometheus", rpm:"prometheus~3.10.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-debuginfo", rpm:"prometheus-debuginfo~3.10.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-debugsource", rpm:"prometheus-debugsource~3.10.0~1.fc42", rls:"FC42"))) {
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
