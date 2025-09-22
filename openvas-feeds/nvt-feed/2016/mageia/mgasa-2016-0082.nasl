# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131243");
  script_cve_id("CVE-2016-0739");
  script_tag(name:"creation_date", value:"2016-02-25 07:28:26 +0000 (Thu, 25 Feb 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 13:25:21 +0000 (Mon, 18 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0082");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0082.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17809");
  script_xref(name:"URL", value:"https://www.libssh.org/2016/02/23/libssh-0-7-3-security-and-bugfix-release/");
  script_xref(name:"URL", value:"https://www.libssh.org/security/advisories/CVE-2016-0739.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the MGASA-2016-0082 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libssh packages fix security vulnerability:

libssh versions 0.1 and above have a bits/bytes confusion bug and generate an
abnormally short ephemeral secret for the diffie-hellman-group1 and
diffie-hellman-group14 key exchange methods. The resulting secret is 128 bits
long, instead of the recommended sizes of 1024 and 2048 bits respectively.
Both client and server are vulnerable, pre-authentication. This
vulnerability could be exploited by an eavesdropper with enough resources to
decrypt or intercept SSH sessions (CVE-2016-0739).");

  script_tag(name:"affected", value:"'libssh' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh-devel", rpm:"lib64ssh-devel~0.6.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh4", rpm:"lib64ssh4~0.6.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh", rpm:"libssh~0.6.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.6.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4", rpm:"libssh4~0.6.5~1.1.mga5", rls:"MAGEIA5"))) {
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
