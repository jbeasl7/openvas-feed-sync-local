# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0361");
  script_cve_id("CVE-2020-15810", "CVE-2020-15811", "CVE-2020-24606");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-03 16:25:56 +0000 (Thu, 03 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0361)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0361");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0361.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27211");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-3365-q9qx-f98m");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-c7p8-xqhm-49wv");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-vvj7-xjgq-g2jg");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2020-0361 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Squid before 4.13. Due to incorrect data validation,
HTTP Request Smuggling attacks may succeed against HTTP and HTTPS traffic.
This leads to cache poisoning. This allows any client, including browser
scripts, to bypass local security and poison the proxy cache and any downstream
caches with content from an arbitrary source. When configured for relaxed
header parsing (the default), Squid relays headers containing whitespace
characters to upstream servers. When this occurs as a prefix to a
Content-Length header, the frame length specified will be ignored by Squid
(allowing for a conflicting length to be used from another Content-Length
header) but relayed upstream (CVE-2020-15810).

An issue was discovered in Squid before 4.13. Due to incorrect data validation,
HTTP Request Splitting attacks may succeed against HTTP and HTTPS traffic. This
leads to cache poisoning. This allows any client, including browser scripts, to
bypass local security and poison the browser cache and any downstream caches
with content from an arbitrary source. Squid uses a string search instead of
parsing the Transfer-Encoding header to find chunked encoding. This allows an
attacker to hide a second request inside Transfer-Encoding: it is interpreted
by Squid as chunked and split out into a second request delivered upstream.
Squid will then deliver two distinct responses to the client, corrupting any
downstream caches (CVE-2020-15811).

Squid before 4.13 and 5.x before 5.0.4 allows a trusted peer to perform Denial
of Service by consuming all available CPU cycles during handling of a crafted
Cache Digest response message. This only occurs when cache_peer is used with
the cache digests feature. The problem exists because peerDigestHandleReply()
livelocking in peer_digest.cc mishandles EOF (CVE-2020-24606).");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.13~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~4.13~1.mga7", rls:"MAGEIA7"))) {
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
