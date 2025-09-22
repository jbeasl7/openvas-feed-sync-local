# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0140");
  script_cve_id("CVE-2024-31497");
  script_tag(name:"creation_date", value:"2024-04-22 04:12:46 +0000 (Mon, 22 Apr 2024)");
  script_version("2024-05-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-05-13 05:05:46 +0000 (Mon, 13 May 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-10 14:33:55 +0000 (Fri, 10 May 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0140)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0140");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0140.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33103");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/04/15/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'filezilla, libfilezilla, putty' package(s) announced via the MGASA-2024-0140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The PuTTY client and all related components generate heavily biased
ECDSA nonces in the case of NIST P-521. To be more precise, the first 9
bits of each ECDSA nonce are zero. This allows for full secret key
recovery in roughly 60 signatures by using state-of-the-art techniques.
These signatures can either be harvested by a malicious server
(man-in-the-middle attacks are not possible given that clients do not
transmit their signature in the clear) or from any other source, e.g.
signed git commits through forwarded agents. The nonce generation for
other curves is slightly biased as well. However, the bias is negligible
and far from enough to perform lattice-based key recovery attacks (not
considering cryptanalytical advancements).");

  script_tag(name:"affected", value:"'filezilla, libfilezilla, putty' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.67.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla-devel", rpm:"lib64filezilla-devel~0.47.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla43", rpm:"lib64filezilla43~0.47.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla", rpm:"libfilezilla~0.47.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla-devel", rpm:"libfilezilla-devel~0.47.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla-i18n", rpm:"libfilezilla-i18n~0.47.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla43", rpm:"libfilezilla43~0.47.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.81~1.mga9", rls:"MAGEIA9"))) {
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
