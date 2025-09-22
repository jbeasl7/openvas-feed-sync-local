# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886869");
  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460", "CVE-2024-32658", "CVE-2024-32659", "CVE-2024-32660", "CVE-2024-32661", "CVE-2024-32662");
  script_tag(name:"creation_date", value:"2024-05-27 10:49:40 +0000 (Mon, 27 May 2024)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:44:06 +0000 (Tue, 04 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-1b11432d52)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-1b11432d52");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-1b11432d52");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276721");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276722");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276724");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276725");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276726");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276733");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276738");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276743");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276749");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276755");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276759");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276804");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276807");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276961");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276966");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276968");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276970");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276971");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276974");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276980");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276986");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the FEDORA-2024-1b11432d52 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.11.7 (CVE-2024-32039, CVE-2024-32040, CVE-2024-32041, CVE-2024-32458, CVE-2024-32459, CVE-2024-32460, CVE-2024-32658, CVE-2024-32659, CVE-2024-32660, CVE-2024-32661, CVE-2024-32662)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs-debuginfo", rpm:"freerdp-libs-debuginfo~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr", rpm:"libwinpr~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr-debuginfo", rpm:"libwinpr-debuginfo~2.11.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr-devel", rpm:"libwinpr-devel~2.11.7~1.fc39", rls:"FC39"))) {
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
