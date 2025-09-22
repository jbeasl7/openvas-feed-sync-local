# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0345");
  script_cve_id("CVE-2022-27939", "CVE-2022-27940", "CVE-2022-27941", "CVE-2022-27942", "CVE-2022-28487", "CVE-2022-37047", "CVE-2022-37048", "CVE-2022-37049");
  script_tag(name:"creation_date", value:"2022-09-26 07:51:41 +0000 (Mon, 26 Sep 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-22 12:58:55 +0000 (Mon, 22 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0345");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0345.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30822");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/5B75AFRJUGOYHCFG2ZV2JKSUPA6MSCT5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpreplay' package(s) announced via the MGASA-2022-0345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tcprewrite in Tcpreplay 4.4.1 has a reachable assertion in get_layer4_v6
in common/get.c. (CVE-2022-27939)

tcprewrite in Tcpreplay 4.4.1 has a heap-based buffer over-read in
get_ipv6_next in common/get.c. (CVE-2022-27940)

tcprewrite in Tcpreplay 4.4.1 has a heap-based buffer over-read in
get_l2len_protocol in common/get.c. (CVE-2022-27941)

tcpprep in Tcpreplay 4.4.1 has a heap-based buffer over-read in parse_mpls
in common/get.c. (CVE-2022-27942)

Tcpreplay version 4.4.1 contains a memory leakage flaw in
fix_ipv6_checksums() function. The highest threat from this vulnerability
is to data confidentiality. (CVE-2022-28487)

The component tcprewrite in Tcpreplay v4.4.1 was discovered to contain a
heap-based buffer overflow in get_ipv6_next at common/get.c:713.
(CVE-2022-37047)

The component tcprewrite in Tcpreplay v4.4.1 was discovered to contain a
heap-based buffer overflow in get_l2len_protocol at common/get.c:344.
(CVE-2022-37048)

The component tcpprep in Tcpreplay v4.4.1 was discovered to contain a
heap-based buffer overflow in parse_mpls at common/get.c:150.
(CVE-2022-37049)");

  script_tag(name:"affected", value:"'tcpreplay' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay", rpm:"tcpreplay~4.4.2~1.mga8", rls:"MAGEIA8"))) {
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
