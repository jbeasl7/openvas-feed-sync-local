# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120190");
  script_cve_id("CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6500", "CVE-2014-6559");
  script_tag(name:"creation_date", value:"2015-09-08 11:19:33 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-428");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-428.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql55' package(s) announced via the ALAS-2014-428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: SERVER:SSL:yaSSL). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Easily exploitable vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized takeover of MySQL Server possibly including arbitrary code execution within the MySQL Server. (CVE-2014-6491)

Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: C API SSL CERTIFICATE HANDLING). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Difficult to exploit vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized read access to all MySQL Server accessible data. (CVE-2014-6559)

Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: SERVER:SSL:yaSSL). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Easily exploitable vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized takeover of MySQL Server possibly including arbitrary code execution within the MySQL Server. (CVE-2014-6500)

Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: CLIENT:SSL:yaSSL). Supported versions that are affected are 5.5.39 and earlier and 5.6.20 and earlier. Difficult to exploit vulnerability allows successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2014-6494)");

  script_tag(name:"affected", value:"'mysql55' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"mysql55", rpm:"mysql55~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-bench", rpm:"mysql55-bench~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-common", rpm:"mysql55-common~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-debuginfo", rpm:"mysql55-debuginfo~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-devel", rpm:"mysql55-devel~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-embedded", rpm:"mysql55-embedded~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-embedded-devel", rpm:"mysql55-embedded-devel~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-libs", rpm:"mysql55-libs~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-server", rpm:"mysql55-server~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-test", rpm:"mysql55-test~5.5.40~1.3.amzn1", rls:"AMAZON"))) {
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
