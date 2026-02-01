# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.010019910221014598");
  script_cve_id("CVE-2025-9615");
  script_tag(name:"creation_date", value:"2026-01-13 04:20:59 +0000 (Tue, 13 Jan 2026)");
  script_version("2026-01-27T05:49:07+0000");
  script_tag(name:"last_modification", value:"2026-01-27 05:49:07 +0000 (Tue, 27 Jan 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-26 20:16:09 +0000 (Mon, 26 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-0d1cf2e45b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-0d1cf2e45b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-0d1cf2e45b");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager-l2tp' package(s) announced via the FEDORA-2026-0d1cf2e45b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated to 1.52.0 release (CVE-2025-9615)
Verify file permissions for private connections to prevent
unprivileged user from using other user's certs.

Ensure NetworkManager dependency has CVE-2025-9615 update.");

  script_tag(name:"affected", value:"'NetworkManager-l2tp' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-l2tp", rpm:"NetworkManager-l2tp~1.52.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-l2tp-debuginfo", rpm:"NetworkManager-l2tp-debuginfo~1.52.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-l2tp-debugsource", rpm:"NetworkManager-l2tp-debugsource~1.52.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-l2tp-gnome", rpm:"NetworkManager-l2tp-gnome~1.52.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-l2tp-gnome-debuginfo", rpm:"NetworkManager-l2tp-gnome-debuginfo~1.52.0~1.fc42", rls:"FC42"))) {
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
