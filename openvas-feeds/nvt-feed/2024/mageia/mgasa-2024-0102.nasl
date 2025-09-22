# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0102");
  script_cve_id("CVE-2023-46724", "CVE-2023-49285", "CVE-2023-49286", "CVE-2023-50269", "CVE-2024-23638", "CVE-2024-25111", "CVE-2024-25617");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-09 13:51:19 +0000 (Thu, 09 Jan 2025)");

  script_name("Mageia: Security Advisory (MGASA-2024-0102)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0102");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0102.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33003");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2024/msg00043.html");
  script_xref(name:"URL", value:"https://lwn.net/Articles/966404/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2024-0102 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to an Improper Validation of Specified Index bug, Squid versions
3.3.0.1 through 5.9 and 6.0 prior to 6.4 compiled using `--with-openssl`
are vulnerable to a Denial of Service attack against SSL Certificate
validation. This problem allows a remote server to perform Denial of
Service against Squid Proxy by initiating a TLS Handshake with a
specially crafted SSL Certificate in a server certificate chain. This
attack is limited to HTTPS and SSL-Bump. (CVE-2023-46724)
Due to a Buffer Overread bug Squid is vulnerable to a Denial of Service
attack against Squid HTTP Message processing. (CVE-2023-49285)
Due to an Incorrect Check of Function Return Value bug Squid is
vulnerable to a Denial of Service attack against its Helper process
management. (CVE-2023-49286)
Due to an Uncontrolled Recursion bug in versions 2.6 through
2.7.STABLE9, versions 3.1 through 5.9, and versions 6.0.1 through 6.5,
Squid may be vulnerable to a Denial of Service attack against HTTP
Request parsing. This problem allows a remote client to perform Denial
of Service attack by sending a large X-Forwarded-For header when the
follow_x_forwarded_for feature is configured. (CVE-2023-50269)
Due to an expired pointer reference bug, Squid prior to version 6.6 is
vulnerable to a Denial of Service attack against Cache Manager error
responses. This problem allows a trusted client to perform Denial of
Service when generating error pages for Client Manager reports.
(CVE-2024-23638)
 Starting in version 3.5.27 and prior to version 6.8, Squid may be
vulnerable to a Denial of Service attack against HTTP Chunked decoder
due to an uncontrolled recursion bug. This problem allows a remote
attacker to cause Denial of Service when sending a crafted, chunked,
encoded HTTP Message. (CVE-2024-25111)
Due to a Collapse of Data into Unsafe Value bug ,Squid may be vulnerable
to a Denial of Service attack against HTTP header parsing. This problem
allows a remote client or a remote server to perform Denial of Service
when sending oversized headers in HTTP messages. In versions of Squid
prior to 6.5 this can be achieved if the request_header_max_size or
reply_header_max_size settings are unchanged from the default.
(CVE-2024-25617)");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~5.9~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~5.9~1.2.mga9", rls:"MAGEIA9"))) {
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
