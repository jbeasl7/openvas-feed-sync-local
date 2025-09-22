# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0129");
  script_cve_id("CVE-2025-31160");
  script_tag(name:"creation_date", value:"2025-04-10 04:07:53 +0000 (Thu, 10 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0129)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0129");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0129.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34139");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00054.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3K7T3QBXEP6TWTVJEMB47AVS2B2R5O5V/");
  script_xref(name:"URL", value:"https://news.ycombinator.com/item?id=43477057");
  script_xref(name:"URL", value:"https://news.ycombinator.com/item?id=43485980");
  script_xref(name:"URL", value:"https://rachelbythebay.com/w/2025/03/26/atop/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/03/26/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/03/26/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/03/29/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'atop' package(s) announced via the MGASA-2025-0129 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"atop through 2.11.0 allows local users to cause a denial of service
(e.g., assertion failure and application exit) or possibly have
unspecified other impact by running certain types of unprivileged
processes while a different user runs atop. (CVE-2025-31160)");

  script_tag(name:"affected", value:"'atop' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"atop", rpm:"atop~2.8.1~1.1.mga9", rls:"MAGEIA9"))) {
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
