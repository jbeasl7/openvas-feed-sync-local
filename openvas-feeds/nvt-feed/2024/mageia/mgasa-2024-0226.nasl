# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0226");
  script_cve_id("CVE-2024-26306");
  script_tag(name:"creation_date", value:"2024-06-18 04:11:36 +0000 (Tue, 18 Jun 2024)");
  script_version("2024-06-18T05:05:55+0000");
  script_tag(name:"last_modification", value:"2024-06-18 05:05:55 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0226)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0226");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0226.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33296");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035556.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iperf' package(s) announced via the MGASA-2024-0226 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"iPerf3 before 3.17, when used with OpenSSL before 3.2.0 as a server with
RSA authentication, allows a timing side channel in RSA decryption
operations. This side channel could be sufficient for an attacker to
recover credential plaintext. It requires the attacker to send a large
number of messages for decryption, as described in 'Everlasting ROBOT:
the Marvin Attack' by Hubert Kario.");

  script_tag(name:"affected", value:"'iperf' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"iperf", rpm:"iperf~3.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64iperf-devel", rpm:"lib64iperf-devel~3.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64iperf0", rpm:"lib64iperf0~3.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf-devel", rpm:"libiperf-devel~3.17.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0", rpm:"libiperf0~3.17.1~1.mga9", rls:"MAGEIA9"))) {
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
