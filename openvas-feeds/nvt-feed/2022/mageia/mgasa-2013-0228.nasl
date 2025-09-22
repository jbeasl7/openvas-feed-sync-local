# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0228");
  script_cve_id("CVE-2013-4115", "CVE-2013-4123");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0228)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0228");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0228.html");
  script_xref(name:"URL", value:"ftp://ftp.fu-berlin.de/unix/www/squid/archive/3.2/squid-3.2.0.9-RELEASENOTES.html#ss2.4");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2013_2.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2013_3.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Doc/man/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10516");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2013-0228 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to incorrect data validation Squid is vulnerable to a buffer overflow
attack when processing specially crafted HTTP requests. This problem allows
any trusted client or client script who can generate HTTP requests to trigger
a buffer overflow in Squid, resulting in a termination of the Squid service
(CVE-2013-4115).

Due to incorrect data validation Squid is vulnerable to a denial of service
attack when processing specially crafted HTTP requests. This problem allows
any client who can generate HTTP requests to perform a denial of service
attack on the Squid service (CVE-2013-4123).

Also, due to being renamed in Squid 3.2, the Squid external acl helpers for
matching against IP addresses and LDAP groups were not selected to be built
in the squid package for Mageia 3.

This has been corrected and these helpers are now included. Additionally,
the helpers for eDirectory IP address lookups and matching LDAP groups using
Kerberos credentials have also been included.");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.2.10~1.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~3.2.10~1.4.mga3", rls:"MAGEIA3"))) {
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
