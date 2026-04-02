# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.65198974626102");
  script_cve_id("CVE-2026-28417", "CVE-2026-28418", "CVE-2026-28419", "CVE-2026-28420", "CVE-2026-28421", "CVE-2026-28422");
  script_tag(name:"creation_date", value:"2026-03-09 04:44:32 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-04 20:47:36 +0000 (Wed, 04 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-651ba4626f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-651ba4626f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-651ba4626f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443455");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443474");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443475");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443481");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443482");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443484");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443790");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the FEDORA-2026-651ba4626f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fixes for CVE-2026-28417, CVE-2026-28418, CVE-2026-28419, CVE-2026-28420, CVE-2026-28421, CVE-2026-28422

----

Security fixes for CVE-2026-28417, CVE-2026-28418, CVE-2026-28419, CVE-2026-28420, CVE-2026-28421, CVE-2026-28422");

  script_tag(name:"affected", value:"'vim' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-X11-debuginfo", rpm:"vim-X11-debuginfo~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-default-editor", rpm:"vim-default-editor~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced-debuginfo", rpm:"vim-enhanced-debuginfo~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal-debuginfo", rpm:"vim-minimal-debuginfo~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xxd", rpm:"xxd~9.2.112~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xxd-debuginfo", rpm:"xxd-debuginfo~9.2.112~2.fc43", rls:"FC43"))) {
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
