# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887301");
  script_cve_id("CVE-2024-29421");
  script_tag(name:"creation_date", value:"2024-08-06 07:33:14 +0000 (Tue, 06 Aug 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-3dbd2c53ac)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-3dbd2c53ac");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-3dbd2c53ac");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283099");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283100");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283157");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmedcon' package(s) announced via the FEDORA-2024-3dbd2c53ac advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- update xmedcon to 0.24.0
- fixes:
Bug 2283157 - xmedcon-0.24.0 is available
Bug 2283100 - CVE-2024-29421 xmedcon: Heap overview when parsing DICOM medical files [fedora-all]
Bug 2283099 (CVE-2024-29421) - CVE-2024-29421 xmedcon: Heap overview when parsing DICOM medical files");

  script_tag(name:"affected", value:"'xmedcon' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"xmedcon", rpm:"xmedcon~0.24.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmedcon-debuginfo", rpm:"xmedcon-debuginfo~0.24.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmedcon-debugsource", rpm:"xmedcon-debugsource~0.24.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmedcon-devel", rpm:"xmedcon-devel~0.24.0~1.fc39", rls:"FC39"))) {
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
