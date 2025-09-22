# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131313");
  script_cve_id("CVE-2016-3947", "CVE-2016-3948");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:14 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-08 16:36:26 +0000 (Fri, 08 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0133");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0133.html");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_3.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_4.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18122");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2016-0133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated squid packages fix security vulnerabilities:

Due to a buffer overrun, the Squid pinger binary in Squid before 3.5.16 is
vulnerable to a denial of service or information leak attack when processing
ICMPv6 packets. This bug also permits the server response to manipulate other
ICMP and ICMPv6 queries processing to cause information leaks (CVE-2016-3947).

Due to incorrect bounds checking, Squid before 3.5.16 is vulnerable to a
denial of service attack when processing HTTP responses (CVE-2016-3948).");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~3.5.16~1.mga5", rls:"MAGEIA5"))) {
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
