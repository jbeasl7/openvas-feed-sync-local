# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.99590910110297599");
  script_cve_id("CVE-2024-22373", "CVE-2024-22391", "CVE-2024-25569");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 18:04:45 +0000 (Thu, 21 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-c5909efa5c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c5909efa5c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c5909efa5c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245816");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277288");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277292");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277296");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdcm' package(s) announced via the FEDORA-2024-c5909efa5c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for gdcm-3.0.23-5.fc41.

##### **Changelog**

```
* Fri Apr 26 2024 Sandro <devel@penguinpee.nl> - 3.0.23-5
- Apply security patches
- Fix TALOS-2024-1924, CVE-2024-22391 (RHBZ#2277288)
- Fix TALOS-2024-1935, CVE-2024-22373 (RHBZ#2277292)
- Fix TALOS-2024-1944, CVE-2024-25569 (RHBZ#2277296)
* Fri Apr 19 2024 Sandro <devel@penguinpee.nl> - 3.0.23-4
- Replace deprecated PyEval_CallObject() (RHBZ#2245816)
* Fri Mar 22 2024 Sergio M. Basto <sergio@serjux.com> - 3.0.23-3
- Update URL

```");

  script_tag(name:"affected", value:"'gdcm' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdcm", rpm:"gdcm~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-applications", rpm:"gdcm-applications~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-applications-debuginfo", rpm:"gdcm-applications-debuginfo~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-debuginfo", rpm:"gdcm-debuginfo~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-debugsource", rpm:"gdcm-debugsource~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-devel", rpm:"gdcm-devel~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-doc", rpm:"gdcm-doc~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gdcm", rpm:"python3-gdcm~3.0.23~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gdcm-debuginfo", rpm:"python3-gdcm-debuginfo~3.0.23~5.fc41", rls:"FC41"))) {
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
