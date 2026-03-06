# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9929854519835");
  script_cve_id("CVE-2025-13609", "CVE-2026-1709");
  script_tag(name:"creation_date", value:"2026-03-04 04:36:20 +0000 (Wed, 04 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-06 20:16:09 +0000 (Fri, 06 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-c2b5451b35)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-c2b5451b35");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-c2b5451b35");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2395216");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2416806");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2435514");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keylime, keylime-agent-rust' package(s) announced via the FEDORA-2026-c2b5451b35 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update keylime to version 7.14.1 and keylime-agent-rust to version 0.2.9

Fixes: CVE-2026-1709 and CVE-2025-13609");

  script_tag(name:"affected", value:"'keylime, keylime-agent-rust' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"keylime", rpm:"keylime~7.14.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust", rpm:"keylime-agent-rust~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-common", rpm:"keylime-agent-rust-common~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-debuginfo", rpm:"keylime-agent-rust-debuginfo~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-debugsource", rpm:"keylime-agent-rust-debugsource~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-ima-emulator", rpm:"keylime-agent-rust-ima-emulator~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-ima-emulator-debuginfo", rpm:"keylime-agent-rust-ima-emulator-debuginfo~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-push", rpm:"keylime-agent-rust-push~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-push-debuginfo", rpm:"keylime-agent-rust-push-debuginfo~0.2.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-base", rpm:"keylime-base~7.14.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-registrar", rpm:"keylime-registrar~7.14.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-selinux", rpm:"keylime-selinux~7.14.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tenant", rpm:"keylime-tenant~7.14.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tools", rpm:"keylime-tools~7.14.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-verifier", rpm:"keylime-verifier~7.14.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-keylime", rpm:"python3-keylime~7.14.1~1.fc42", rls:"FC42"))) {
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
