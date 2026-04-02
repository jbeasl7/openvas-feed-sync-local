# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1363");
  script_cve_id("CVE-2025-47912", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58186", "CVE-2025-58187", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61724", "CVE-2025-61727", "CVE-2025-61729");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for golang (EulerOS-SA-2026-1363)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1363");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1363");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'golang' package(s) announced via the EulerOS-SA-2026-1363 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Reader.ReadResponse function constructs a response string through repeated string concatenation of lines. When the number of lines in a response is large, this can cause excessive CPU consumption.(CVE-2025-61724)

Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exhaustion.(CVE-2025-58185)

tar.Reader does not set a maximum size on the number of sparse region data blocks in GNU tar pax 1.0 sparse files. A maliciously-crafted archive containing a large number of sparse regions can cause a Reader to read an unbounded amount of data from the archive into memory. When reading from a compressed source, a small compressed input can result in large allocations.(CVE-2025-58183)

Despite HTTP headers having a default limit of 1MB, the number of cookies that can be parsed does not have a limit. By sending a lot of very small cookies such as 'a=,', an attacker can make an HTTP server allocate a large amount of structs, causing large memory consumption.(CVE-2025-58186)

The Parse function permits values other than IPv6 addresses to be included in square brackets within the host component of a URL. RFC 3986 permits IPv6 addresses to be included within the host component, enclosed within square brackets. For example: 'http://[::1]/'. IPv4 addresses and hostnames must not appear within square brackets. Parse did not enforce this requirement.(CVE-2025-47912)

Within HostnameError.Error(), when constructing an error string, there is no limit to the number of hosts that will be printed out. Furthermore, the error string is constructed by repeated string concatenation, leading to quadratic runtime. Therefore, a certificate provided by a malicious actor can result in excessive resource consumption.(CVE-2025-61729)

Due to the design of the name constraint checking algorithm, the processing time of some inputs scale non-linearly with respect to the size of the certificate. This affects programs which validate arbitrary certificate chains.(CVE-2025-58187)

The processing time for parsing some invalid inputs scales non-linearly with respect to the size of the input. This affects programs which parse untrusted PEM inputs.(CVE-2025-61723)

When Conn.Handshake fails during ALPN negotiation the error contains attacker controlled information (the ALPN protocols sent by the client) which is not escaped.(CVE-2025-58189)

An excluded subdomain constraint in a certificate chain does not restrict the usage of wildcard SANs in the leaf certificate. For example a constraint that excludes the subdomain test.example.com does not prevent a leaf certificate from claiming the SAN *.example.com.(CVE-2025-61727)");

  script_tag(name:"affected", value:"'golang' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.17.3~12.h33.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-devel", rpm:"golang-devel~1.17.3~12.h33.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-help", rpm:"golang-help~1.17.3~12.h33.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
