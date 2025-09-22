# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0264");
  script_cve_id("CVE-2024-3596");
  script_tag(name:"creation_date", value:"2024-07-15 04:11:26 +0000 (Mon, 15 Jul 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-30 19:23:20 +0000 (Mon, 30 Dec 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0264");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0264.html");
  script_xref(name:"URL", value:"https://blastradius.fail");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33388");
  script_xref(name:"URL", value:"https://www.freeradius.org/security/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/09/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius' package(s) announced via the MGASA-2024-0264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability allows an attacker performing a meddler-in-the-middle
attack between Palo Alto Networks PAN-OS firewall and a RADIUS server to
bypass authentication and escalate privileges to 'superuser' when RADIUS
authentication is in use and either CHAP or PAP is selected in the
RADIUS server profile.
CHAP and PAP are protocols with no Transport Layer Security (TLS), and
hence vulnerable to meddler-in-the-middle attacks. Neither protocol
should be used unless they are encapsulated by an encrypted tunnel. If
they are in use, but are encapsulated within a TLS tunnel, they are not
vulnerable to this attack.
For additional information regarding this vulnerability, please see
[link moved to references].
Note: these two lines are added upstream in the default radiusd.conf
file:
'''
require_message_authenticator = auto
limit_proxy_state = auto
'''");

  script_tag(name:"affected", value:"'freeradius' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-krb5", rpm:"freeradius-krb5~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-ldap", rpm:"freeradius-ldap~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-mysql", rpm:"freeradius-mysql~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-postgresql", rpm:"freeradius-postgresql~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-sqlite", rpm:"freeradius-sqlite~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-unixODBC", rpm:"freeradius-unixODBC~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-yubikey", rpm:"freeradius-yubikey~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeradius-devel", rpm:"lib64freeradius-devel~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeradius1", rpm:"lib64freeradius1~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeradius-devel", rpm:"libfreeradius-devel~3.0.27~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeradius1", rpm:"libfreeradius1~3.0.27~1.mga9", rls:"MAGEIA9"))) {
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
