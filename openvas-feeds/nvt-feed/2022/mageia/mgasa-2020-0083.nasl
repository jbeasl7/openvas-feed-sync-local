# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0083");
  script_cve_id("CVE-2019-16785", "CVE-2019-16786", "CVE-2019-16789");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 21:45:53 +0000 (Wed, 08 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0083");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0083.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26014");
  script_xref(name:"URL", value:"https://docs.pylonsproject.org/projects/waitress/en/latest/#security-fixes");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-waitress' package(s) announced via the MGASA-2020-0083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-waitress packages fix security vulnerabilities:

If a front-end server does not parse header fields with an LF the same
way as it does those with a CRLF it can lead to the front-end and the
back-end server parsing the same HTTP message in two different ways.
This can lead to a potential for HTTP request smuggling/splitting whereby
Waitress may see two requests while the front-end server only sees a
single HTTP message (CVE-2019-16785).

Waitress through version 1.3.1 would parse the Transfer-Encoding header
and only look for a single string value, if that value was not chunked
it would fall through and use the Content-Length header instead. This
could allow for Waitress to treat a single request as multiple requests
in the case of HTTP pipelining (CVE-2019-16786).

In Waitress through version 1.4.0, if a proxy server is used in front of
waitress, an invalid request may be sent by an attacker that bypasses the
front-end and is parsed differently by waitress leading to a potential for
HTTP request smuggling. If a front-end server does HTTP pipelining to a
backend Waitress server this could lead to HTTP request splitting which
may lead to potential cache poisoning or unexpected information disclosure
(CVE-2019-16789).");

  script_tag(name:"affected", value:"'python-waitress' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"python-waitress", rpm:"python-waitress~1.4.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-waitress", rpm:"python3-waitress~1.4.2~1.mga7", rls:"MAGEIA7"))) {
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
