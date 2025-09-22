# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2957");
  script_cve_id("CVE-2023-27043", "CVE-2024-0397", "CVE-2024-3219", "CVE-2024-4032", "CVE-2024-6232", "CVE-2024-6923", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"creation_date", value:"2024-12-12 04:32:26 +0000 (Thu, 12 Dec 2024)");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:02:16 +0000 (Tue, 20 Aug 2024)");

  script_name("Huawei EulerOS: Security Advisory for python3 (EulerOS-SA-2024-2957)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2957");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2957");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python3' package(s) announced via the EulerOS-SA-2024-2957 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a MEDIUM severity vulnerability affecting CPython. The 'socket' module provides a pure-Python fallback to the socket.socketpair() function for platforms that don't support AF_UNIX, such as Windows. This pure-Python implementation uses AF_INET or AF_INET6 to create a local connected pair of sockets. The connection between the two sockets was not verified before passing the two sockets back to the user, which leaves the server socket vulnerable to a connection race from a malicious local peer. Platforms that support AF_UNIX such as Linux and macOS are not affected by this vulnerability. Versions prior to CPython 3.5 are not affected due to the vulnerable API not being included.(CVE-2024-3219)

There is a MEDIUM severity vulnerability affecting CPython.Regular expressions that allowed excessive backtracking during tarfile.TarFile header parsing are vulnerable to ReDoS via specifically-crafted tar archives.(CVE-2024-6232)

There is a HIGH severity vulnerability affecting the CPython 'zipfile' module affecting 'zipfile.Path'. Note that the more common API 'zipfile.ZipFile' class is unaffected. When iterating over names of entries in a zip archive (for example, methods of 'zipfile.Path' like 'namelist()', 'iterdir()', etc) the process can be put into an infinite loop with a maliciously crafted zip archive. This defect applies when reading only metadata or extracting the contents of the zip archive. Programs that are not handling user-controlled zip archives are not affected.(CVE-2024-8088)

There is a MEDIUM severity vulnerability affecting CPython. The email module didn't properly quote newlines for email headers when serializing an email message allowing for header injection when an email is serialized.(CVE-2024-6923)

There is a LOW severity vulnerability affecting CPython, specifically the 'http.cookies' standard library module. When parsing cookies that contained backslashes for quoted characters in the cookie value, the parser would use an algorithm with quadratic complexity, resulting in excess CPU resources being used while parsing the value.(CVE-2024-7592)

A defect was discovered in the Python 'ssl' module where there is a memory race condition with the ssl.SSLContext methods 'cert_store_stats()' and 'get_ca_certs()'. The race condition can be triggered if the methods are called at the same time as certificates are loaded into the SSLContext, such as during the TLS handshake with a certificate directory configured. This issue is fixed in CPython 3.10.14, 3.11.9, 3.12.3, and 3.13.0a5.(CVE-2024-0397)

The 'ipaddress' module contained incorrect information about whether certain IPv4 and IPv6 addresses were designated as 'globally reachable' or 'private'. This affected the is_private and is_global properties of the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network classes, where values wouldn't be returned in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python3' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.9.9~21.h14.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fgo", rpm:"python3-fgo~3.9.9~21.h14.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unversioned-command", rpm:"python3-unversioned-command~3.9.9~21.h14.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
