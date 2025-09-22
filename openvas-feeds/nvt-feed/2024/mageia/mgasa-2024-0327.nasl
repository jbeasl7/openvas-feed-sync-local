# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0327");
  script_cve_id("CVE-2024-47076", "CVE-2024-47175", "CVE-2024-47176", "CVE-2024-47177");
  script_tag(name:"creation_date", value:"2024-10-08 04:10:52 +0000 (Tue, 08 Oct 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0327");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0327.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33596");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7041-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7043-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/09/26/5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups, cups-filters' package(s) announced via the MGASA-2024-0327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The `cfGetPrinterAttributes5` function in `libcupsfilters` does not
sanitize IPP attributes returned from an IPP server. When these IPP
attributes are used, for instance, to generate a PPD file, this can lead
to attacker controlled data to be provided to the rest of the CUPS
system. (CVE-2024-47076)
The `libppd` function `ppdCreatePPDFromIPP2` does not sanitize IPP
attributes when creating the PPD buffer. When used in combination with
other functions such as `cfGetPrinterAttributes5`, can result in user
controlled input and ultimately code execution via Foomatic. This
vulnerability can be part of an exploit chain leading to remote code
execution (RCE), as described in CVE-2024-47176. (CVE-2024-47175)
`cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet
from any source, and can cause the `Get-Printer-Attributes` IPP request
to an attacker controlled URL. When combined with other vulnerabilities,
such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker
can execute arbitrary commands remotely on the target machine without
authentication when a malicious printer is printed to. (CVE-2024-47176)
Any value passed to `FoomaticRIPCommandLine` via a PPD file will be
executed as a user controlled command. When combined with other logic
bugs as described in CVE_2024-47176, this can lead to remote command
execution. (CVE-2024-47177)");

  script_tag(name:"affected", value:"'cups, cups-filters' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filesystem", rpm:"cups-filesystem~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.28.16~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-printerapp", rpm:"cups-printerapp~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters-devel", rpm:"lib64cups-filters-devel~1.28.16~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters1", rpm:"lib64cups-filters1~1.28.16~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters-devel", rpm:"libcups-filters-devel~1.28.16~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters1", rpm:"libcups-filters1~1.28.16~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~2.4.6~1.3.mga9", rls:"MAGEIA9"))) {
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
