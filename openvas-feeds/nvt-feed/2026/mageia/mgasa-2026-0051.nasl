# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0051");
  script_cve_id("CVE-2026-27624");
  script_tag(name:"creation_date", value:"2026-03-10 04:38:08 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-27 18:04:29 +0000 (Fri, 27 Feb 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0051");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0051.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35179");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/37LHFMZ3OPUJRL3DZ3WVCJ7FO62HMVUT/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coturn' package(s) announced via the MGASA-2026-0051 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IPv4-mapped IPv6 (::ffff:0:0/96) bypasses denied-peer-ip ACL.
(CVE-2026-27624)");

  script_tag(name:"affected", value:"'coturn' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"coturn", rpm:"coturn~4.6.2~1.1.mga9", rls:"MAGEIA9"))) {
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
