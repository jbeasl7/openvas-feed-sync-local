# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.191.01");
  script_cve_id("CVE-2025-32988", "CVE-2025-32989", "CVE-2025-32990", "CVE-2025-6395");
  script_tag(name:"creation_date", value:"2025-07-11 04:20:48 +0000 (Fri, 11 Jul 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 19:32:53 +0000 (Fri, 15 Aug 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-191-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-191-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.436167");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-32988");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-32989");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-32990");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6395");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SSA:2025-191-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Message-ID: <alpine.LNX.2.02.2507101641590.5490@connie.slackware.com>
User-Agent: Alpine 2.02 (LNX 1266 2009-07-14)
MIME-Version: 1.0
Content-Type: MULTIPART/MIXED, BOUNDARY='960504934-1586331464-1752190934=:5490'

 This message is in MIME format. The first part should be readable text,
 while the remaining parts are likely unreadable without MIME-aware tools.

--960504934-1586331464-1752190934=:5490
Content-Type: TEXT/PLAIN, charset=ISO-8859-1
Content-Transfer-Encoding: 8BIT


-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

[slackware-security] gnutls (SSA:2025-191-01)

New gnutls packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/gnutls-3.8.10-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 libgnutls: Fix NULL pointer dereference when 2nd Client Hello omits PSK.
 Reported by Stefan B??hler
 libgnutls: Fix heap read buffer overrun in parsing X.509 SCTS timestamps.
 Spotted by oss-fuzz and reported by OpenAI Security Research Team,
 and fix developed by Andrew Hamilton.
 libgnutls: Fix double-free upon error when exporting otherName in SAN.
 Reported by OpenAI Security Research Team.
 certtool: Fix 1-byte write buffer overrun when parsing template.
 Reported by David Aitel.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gnutls' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.10-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.10-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.10-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.10-x86_64-1", rls:"SLKcurrent"))) {
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
