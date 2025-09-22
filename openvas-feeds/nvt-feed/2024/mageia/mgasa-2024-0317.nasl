# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0317");
  script_cve_id("CVE-2015-2104", "CVE-2023-27043", "CVE-2024-0397", "CVE-2024-4032", "CVE-2024-6232", "CVE-2024-6923", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"creation_date", value:"2024-09-27 04:11:17 +0000 (Fri, 27 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:02:16 +0000 (Tue, 20 Aug 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0317)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0317");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0317.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33436");
  script_xref(name:"URL", value:"https://lwn.net/Articles/983060/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/06/17/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/06/17/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/08/01/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/08/22/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/09/03/5");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/09/07/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the MGASA-2024-0317 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A defect was discovered in the Python 'ssl' module where there is a
memory race condition with the ssl.SSLContext methods
'cert_store_stats()' and 'get_ca_certs()'. The race condition can be
triggered if the methods are called at the same time as certificates are
loaded into the SSLContext, such as during the TLS handshake with a
certificate directory configured. (CVE-2024-0397)
The 'ipaddress' module contained incorrect information about whether
certain IPv4 and IPv6 addresses were designated as 'globally reachable'
or 'private'. This affected the is_private and is_global properties of
the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address,
and ipaddress.IPv6Network classes, where values wouldn't be returned in
accordance with the latest information from the IANA Special-Purpose
Address Registries. (CVE-2024-4032)
The email module didn't properly quote newlines for email headers when
serializing an email message allowing for header injection when an email
is serialized. (CVE-2024-6923)
When iterating over names of entries in a zip archive (for example,
methods of 'zipfile.Path' like 'namelist()', 'iterdir()', etc) the
process can be put into an infinite loop with a maliciously crafted zip
archive. This defect applies when reading only metadata or extracting
the contents of the zip archive. Programs that are not handling
user-controlled zip archives are not affected. (CVE-2024-8088)
Regular expressions that allowed excessive backtracking during
tarfile.TarFile header parsing are vulnerable to ReDoS via
specifically-crafted tar archives. (CVE-2024-6232)
When parsing cookies that contained backslashes for quoted characters in
the cookie value, the parser would use an algorithm with quadratic
complexity, resulting in excess CPU resources being used while parsing
the value. (CVE-2024-7592)
Urlparse insufficient validation leads to open redirect. (CVE-2015-2104)
The email module of Python through 3.11.3 incorrectly parses e-mail
addresses that contain a special character. The wrong portion of an
RFC2822 header is identified as the value of the addr-spec. In some
applications, an attacker can bypass a protection mechanism in which
application access is granted only after verifying receipt of e-mail to
a specific domain (e.g., only @company.example.com addresses may be used
for signup). This occurs in email/_parseaddr.py in recent versions of
Python. (CVE-2023-27043)");

  script_tag(name:"affected", value:"'python3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64python3-devel", rpm:"lib64python3-devel~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10", rpm:"lib64python3.10~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-stdlib", rpm:"lib64python3.10-stdlib~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-testsuite", rpm:"lib64python3.10-testsuite~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3-devel", rpm:"libpython3-devel~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10", rpm:"libpython3.10~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-stdlib", rpm:"libpython3.10-stdlib~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-testsuite", rpm:"libpython3.10-testsuite~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3", rpm:"tkinter3~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3-apps", rpm:"tkinter3-apps~3.10.11~1.3.mga9", rls:"MAGEIA9"))) {
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
