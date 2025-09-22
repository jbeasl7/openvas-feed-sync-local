# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0055");
  script_cve_id("CVE-2023-5752");
  script_tag(name:"creation_date", value:"2025-02-13 04:08:38 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-02-13T05:37:41+0000");
  script_tag(name:"last_modification", value:"2025-02-13 05:37:41 +0000 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-03 14:55:50 +0000 (Fri, 03 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2025-0055)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0055");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0055.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33542");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/LNQOIWP4YVW27J2PSFKW5GCWPMU7ZATV/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip' package(s) announced via the MGASA-2025-0055 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mercurial configuration injectable in repo revision when installing via
pip. (CVE-2023-5752)");

  script_tag(name:"affected", value:"'python-pip' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"python-pip", rpm:"python-pip~23.0.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip-doc", rpm:"python-pip-doc~23.0.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip-wheel", rpm:"python-pip-wheel~23.0.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~23.0.1~1.1.mga9", rls:"MAGEIA9"))) {
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
