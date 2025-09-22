# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886443");
  script_cve_id("CVE-2024-22373", "CVE-2024-22391", "CVE-2024-25569");
  script_tag(name:"creation_date", value:"2024-05-27 10:40:58 +0000 (Mon, 27 May 2024)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 18:04:45 +0000 (Thu, 21 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-fae33e6e9f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-fae33e6e9f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-fae33e6e9f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245816");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277284");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277288");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277289");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277292");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277293");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277296");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdcm' package(s) announced via the FEDORA-2024-fae33e6e9f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"### Security fixes

- TALOS-2024-1924, CVE-2024-22391: heap overflow
- TALOS-2024-1935, CVE-2024-22373: out-of-bounds write
- TALOS-2024-1944, CVE-2024-25569: out-of-bounds read

### Bug fixes

- Replace deprecated `PyEval_CallObject` for compatibility with Python 3.13");

  script_tag(name:"affected", value:"'gdcm' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"gdcm", rpm:"gdcm~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-applications", rpm:"gdcm-applications~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-applications-debuginfo", rpm:"gdcm-applications-debuginfo~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-debuginfo", rpm:"gdcm-debuginfo~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-debugsource", rpm:"gdcm-debugsource~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-devel", rpm:"gdcm-devel~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-doc", rpm:"gdcm-doc~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gdcm", rpm:"python3-gdcm~3.0.23~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gdcm-debuginfo", rpm:"python3-gdcm-debuginfo~3.0.23~5.fc40", rls:"FC40"))) {
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
