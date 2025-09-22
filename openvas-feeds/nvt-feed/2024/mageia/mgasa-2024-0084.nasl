# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0084");
  script_cve_id("CVE-2022-45061", "CVE-2022-48565", "CVE-2022-48566", "CVE-2023-24329", "CVE-2023-40217");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 13:36:41 +0000 (Fri, 01 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0084)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0084");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0084.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:2763");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:2860");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:3556");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:3591");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31000");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TZH26JGNZ5XYPZ5SAU3NKSBSPRE5OHTG/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5888-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6139-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python, python3' package(s) announced via the MGASA-2024-0084 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Python before 3.11.1. An unnecessary
quadratic algorithm exists in one path when processing some inputs to
the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
being presented to the decoder could lead to a CPU denial of service.
Hostnames are often supplied by remote servers that could be controlled
by a malicious actor, in such a scenario, they could trigger excessive
CPU consumption on the client attempting to make use of an
attacker-supplied supposed hostname. (CVE-2022-45061)
An XML External Entity (XXE) issue was discovered in Python through
3.9.1. The plistlib module no longer accepts entity declarations in XML
plist files to avoid XML vulnerabilities. (CVE-2022-48565)
An issue was discovered in compare_digest in Lib/hmac.py in Python
through 3.9.1. Constant-time-defeating optimisations were possible in
the accumulator variable in hmac.compare_digest. (CVE-2022-48566)
An issue in the urllib.parse component of Python before 3.11.4 allows
attackers to bypass blocklisting methods by supplying a URL that starts
with blank characters. (CVE-2023-24329)
An issue was discovered in Python before 3.8.18, 3.9.x before 3.9.18,
3.10.x before 3.10.13, and 3.11.x before 3.11.5. It primarily affects
servers (such as HTTP servers) that use TLS client authentication. If a
TLS server-side socket is created, receives data into the socket buffer,
and then is closed quickly, there is a brief window where the SSLSocket
instance will detect the socket as 'not connected' and won't initiate a
handshake, but buffered data will still be readable from the socket
buffer. This data will not be authenticated if the server-side TLS peer
is expecting client certificate authentication, and is indistinguishable
from valid TLS stream data. Data is limited in size to the amount that
will fit in the buffer. (The TLS connection cannot directly be used for
data exfiltration because the vulnerable code path requires that the
connection be closed on initialization of the SSLSocket).
(CVE-2023-40217)");

  script_tag(name:"affected", value:"'python, python3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64python-devel", rpm:"lib64python-devel~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7", rpm:"lib64python2.7~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-stdlib", rpm:"lib64python2.7-stdlib~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-testsuite", rpm:"lib64python2.7-testsuite~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3-devel", rpm:"lib64python3-devel~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10", rpm:"lib64python3.10~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-stdlib", rpm:"lib64python3.10-stdlib~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-testsuite", rpm:"lib64python3.10-testsuite~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython-devel", rpm:"libpython-devel~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7", rpm:"libpython2.7~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-stdlib", rpm:"libpython2.7-stdlib~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-testsuite", rpm:"libpython2.7-testsuite~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3-devel", rpm:"libpython3-devel~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10", rpm:"libpython3.10~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-stdlib", rpm:"libpython3.10-stdlib~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-testsuite", rpm:"libpython3.10-testsuite~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.7.18~15.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3", rpm:"tkinter3~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3-apps", rpm:"tkinter3-apps~3.10.11~1.1.mga9", rls:"MAGEIA9"))) {
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
