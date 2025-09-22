# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892517");
  script_cve_id("CVE-2020-24386", "CVE-2020-25275");
  script_tag(name:"creation_date", value:"2021-01-11 13:00:50 +0000 (Mon, 11 Jan 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 19:40:58 +0000 (Thu, 07 Jan 2021)");

  script_name("Debian: Security Advisory (DLA-2517-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2517-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2517-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DLA-2517-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were two issues in the Dovecot IMAP server:

CVE-2020-24386

An issue was discovered in Dovecot before 2.3.13. By using IMAP IDLE, an authenticated attacker can trigger unhibernation via attacker-controlled parameters, leading to access to other users' email messages (and path disclosure).

CVE-2020-25275

Dovecot before 2.3.13 has Improper Input Validation in lda, lmtp, and imap, leading to an application crash via a crafted email message with certain choices for ten thousand MIME parts.

For Debian 9 Stretch, these problems have been fixed in version 1:2.2.27-3+deb9u7.

We recommend that you upgrade your dovecot packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.2.27-3+deb9u7", rls:"DEB9"))) {
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
