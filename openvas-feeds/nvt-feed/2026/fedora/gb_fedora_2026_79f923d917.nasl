# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.79102923100917");
  script_cve_id("CVE-2026-22851", "CVE-2026-22852", "CVE-2026-22853", "CVE-2026-22854", "CVE-2026-22855", "CVE-2026-22856", "CVE-2026-22857", "CVE-2026-22858", "CVE-2026-22859");
  script_tag(name:"creation_date", value:"2026-01-19 04:27:49 +0000 (Mon, 19 Jan 2026)");
  script_version("2026-01-21T05:50:46+0000");
  script_tag(name:"last_modification", value:"2026-01-21 05:50:46 +0000 (Wed, 21 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-20 18:34:43 +0000 (Tue, 20 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-79f923d917)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-79f923d917");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-79f923d917");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429784");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429789");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429797");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429803");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429806");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429812");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429816");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429818");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429819");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the FEDORA-2026-79f923d917 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 3.20.2");

  script_tag(name:"affected", value:"'freerdp' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs-debuginfo", rpm:"freerdp-libs-debuginfo~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr", rpm:"libwinpr~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr-debuginfo", rpm:"libwinpr-debuginfo~3.20.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr-devel", rpm:"libwinpr-devel~3.20.2~1.fc43", rls:"FC43"))) {
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
