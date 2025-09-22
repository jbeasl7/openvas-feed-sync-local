# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.83979712829100");
  script_cve_id("CVE-2025-52889", "CVE-2025-52890");
  script_tag(name:"creation_date", value:"2025-08-11 04:19:53 +0000 (Mon, 11 Aug 2025)");
  script_version("2025-08-12T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-83aa12829d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-83aa12829d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-83aa12829d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369373");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2374808");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2374809");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2374810");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2374811");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375609");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375625");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384118");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384130");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384144");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384160");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2385075");
  script_xref(name:"URL", value:"https://github.com/lxc/incus/releases/tag/v6.15.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'incus' package(s) announced via the FEDORA-2025-83aa12829d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New release of Incus. Release information: [link moved to references]");

  script_tag(name:"affected", value:"'incus' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"incus", rpm:"incus~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-agent", rpm:"incus-agent~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-agent-debuginfo", rpm:"incus-agent-debuginfo~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-client", rpm:"incus-client~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-client-debuginfo", rpm:"incus-client-debuginfo~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-debuginfo", rpm:"incus-debuginfo~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-debugsource", rpm:"incus-debugsource~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-selinux", rpm:"incus-selinux~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-tools", rpm:"incus-tools~6.15~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"incus-tools-debuginfo", rpm:"incus-tools-debuginfo~6.15~1.fc41", rls:"FC41"))) {
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
