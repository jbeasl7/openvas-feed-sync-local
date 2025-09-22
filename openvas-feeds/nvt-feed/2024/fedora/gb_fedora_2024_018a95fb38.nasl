# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887259");
  script_tag(name:"creation_date", value:"2024-06-26 04:08:19 +0000 (Wed, 26 Jun 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-018a95fb38)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-018a95fb38");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-018a95fb38");
  script_xref(name:"URL", value:"https://lib.openmpt.org/libopenmpt/2024/05/12/releases-0.7.7-0.6.16-0.5.30-0.4.42/");
  script_xref(name:"URL", value:"https://lib.openmpt.org/libopenmpt/2024/06/09/security-update-0.7.8-releases-0.6.17-0.5.31-0.4.43/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenmpt' package(s) announced via the FEDORA-2024-018a95fb38 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update from 0.7.6 to 0.7.8 for more bug-fixes.
[links moved to references]");

  script_tag(name:"affected", value:"'libopenmpt' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt", rpm:"libopenmpt~0.7.8~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-debuginfo", rpm:"libopenmpt-debuginfo~0.7.8~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-debugsource", rpm:"libopenmpt-debugsource~0.7.8~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-devel", rpm:"libopenmpt-devel~0.7.8~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpt123", rpm:"openmpt123~0.7.8~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpt123-debuginfo", rpm:"openmpt123-debuginfo~0.7.8~1.fc39", rls:"FC39"))) {
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
