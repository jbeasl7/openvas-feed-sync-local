# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0138");
  script_cve_id("CVE-2025-32464");
  script_tag(name:"creation_date", value:"2025-04-28 04:08:25 +0000 (Mon, 28 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0138)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0138");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0138.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34186");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/QIY5CFNUWQY6R6BCFXJMFVWXB3WVUQRS/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7431-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy' package(s) announced via the MGASA-2025-0138 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"BUG/MEDIUM: sample: fix risk of overflow when replacing multiple regex
back-refsAleandro Prudenzano of Doyensec and Edoardo Geraci of Codean
Labs reported a bug in sample_conv_regsub(), which can cause
replacements of multiple back-references to overflow the temporary trash
buffer. The problem happens when doing 'regsub(match,replacement,g)':
we're replacing every occurrence of 'match' with 'replacement' in the
input sample, which requires a length check. For this, a max is applied,
so that a replacement may not use more than the remaining length in the
buffer. However, the length check is made on the replaced pattern and
not on the temporary buffer used to carry the new string. This results
in the remaining size to be usable for each input match, which can go
beyond the temporary buffer size if more than one occurrence has to be
replaced with something that's larger than the remaining room.");

  script_tag(name:"affected", value:"'haproxy' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.8.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-noquic", rpm:"haproxy-noquic~2.8.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-quic", rpm:"haproxy-quic~2.8.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-utils", rpm:"haproxy-utils~2.8.14~1.1.mga9", rls:"MAGEIA9"))) {
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
