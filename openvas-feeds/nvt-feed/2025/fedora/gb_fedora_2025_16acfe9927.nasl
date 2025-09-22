# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1697991021019927");
  script_cve_id("CVE-2025-7039");
  script_tag(name:"creation_date", value:"2025-08-13 04:11:08 +0000 (Wed, 13 Aug 2025)");
  script_version("2025-09-05T05:38:20+0000");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-03 02:15:38 +0000 (Wed, 03 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-16acfe9927)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-16acfe9927");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-16acfe9927");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2' package(s) announced via the FEDORA-2025-16acfe9927 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Resolve CVE-2025-7039 (Buffer Under-read on GLib through glib/gfileutils.c via get_tmp_file()) with several other bug fixes.");

  script_tag(name:"affected", value:"'glib2' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"glib2", rpm:"glib2~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-debuginfo", rpm:"glib2-debuginfo~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-debugsource", rpm:"glib2-debugsource~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-devel", rpm:"glib2-devel~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-devel-debuginfo", rpm:"glib2-devel-debuginfo~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-doc", rpm:"glib2-doc~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-static", rpm:"glib2-static~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tests", rpm:"glib2-tests~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tests-debuginfo", rpm:"glib2-tests-debuginfo~2.84.4~1.fc42", rls:"FC42"))) {
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
