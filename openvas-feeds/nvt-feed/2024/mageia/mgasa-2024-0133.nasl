# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0133");
  script_cve_id("CVE-2023-44271", "CVE-2024-28219");
  script_tag(name:"creation_date", value:"2024-04-16 04:12:33 +0000 (Tue, 16 Apr 2024)");
  script_version("2024-04-16T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-04-16 05:05:31 +0000 (Tue, 16 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 22:01:30 +0000 (Thu, 09 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0133");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0133.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32512");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pillow' package(s) announced via the MGASA-2024-0133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-44271 Denial of Service that uncontrollably allocates memory to
process a given task, potentially causing a service to crash by having
it run out of memory. This occurs for truetype in ImageFont when
textlength in an ImageDraw instance operates on a long text argument.
CVE-2024-28219 A buffer overflow exists because strcpy is used instead
of strncpy.");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~9.2.0~3.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow", rpm:"python3-pillow~9.2.0~3.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-devel", rpm:"python3-pillow-devel~9.2.0~3.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-doc", rpm:"python3-pillow-doc~9.2.0~3.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-qt", rpm:"python3-pillow-qt~9.2.0~3.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-tk", rpm:"python3-pillow-tk~9.2.0~3.2.mga9", rls:"MAGEIA9"))) {
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
