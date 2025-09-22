# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0296");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0296)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0296");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0296.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11148");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-August/114906.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ssmtp' package(s) announced via the MGASA-2013-0296 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that ssmtp, an extremely simple MTA to get mail off the system
to a mail hub, did not perform x509 certificate validation when initiating a
TLS connection to server. A rogue server could use this flaw to conduct man-in-
the-middle attack, possibly leading to user credentials leak.

As a result, alterations may be required to the configuration if using TLS.
The default ssmtp.conf now contains the lines below to load root certificates
which should be created as ssmtp.conf.rpmnew if it has been altered.

#IMPORTANT: Uncomment the following line if you use TLS authentication
#TLS_CA_File=/etc/pki/tls/certs/ca-bundle.crt");

  script_tag(name:"affected", value:"'ssmtp' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"ssmtp", rpm:"ssmtp~2.64~5.3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"ssmtp", rpm:"ssmtp~2.64~8.3.mga3", rls:"MAGEIA3"))) {
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
