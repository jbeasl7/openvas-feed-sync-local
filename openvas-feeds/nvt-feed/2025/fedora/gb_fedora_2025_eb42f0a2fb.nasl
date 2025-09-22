# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1019842102097210298");
  script_cve_id("CVE-2025-58160");
  script_tag(name:"creation_date", value:"2025-09-11 04:05:13 +0000 (Thu, 11 Sep 2025)");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-eb42f0a2fb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-eb42f0a2fb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-eb42f0a2fb");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310970");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-crypto-auditing-agent, rust-crypto-auditing-client, rust-crypto-auditing-event-broker' package(s) announced via the FEDORA-2025-eb42f0a2fb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebuild with tracing-subscriber v0.3.20 for CVE-2025-58160.");

  script_tag(name:"affected", value:"'rust-crypto-auditing-agent, rust-crypto-auditing-client, rust-crypto-auditing-event-broker' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent", rpm:"crypto-auditing-agent~0.2.3~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent-debuginfo", rpm:"crypto-auditing-agent-debuginfo~0.2.3~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-client", rpm:"crypto-auditing-client~0.2.3~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-client-debuginfo", rpm:"crypto-auditing-client-debuginfo~0.2.3~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-event-broker", rpm:"crypto-auditing-event-broker~0.2.3~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-event-broker-debuginfo", rpm:"crypto-auditing-event-broker-debuginfo~0.2.3~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent", rpm:"rust-crypto-auditing-agent~0.2.3~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent-debugsource", rpm:"rust-crypto-auditing-agent-debugsource~0.2.3~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-client", rpm:"rust-crypto-auditing-client~0.2.3~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-client-debugsource", rpm:"rust-crypto-auditing-client-debugsource~0.2.3~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-event-broker", rpm:"rust-crypto-auditing-event-broker~0.2.3~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-event-broker-debugsource", rpm:"rust-crypto-auditing-event-broker-debugsource~0.2.3~5.fc42", rls:"FC42"))) {
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
