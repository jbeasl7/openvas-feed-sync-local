# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64977");
  script_cve_id("CVE-2009-2632", "CVE-2009-3235");
  script_tag(name:"creation_date", value:"2009-09-28 17:09:13 +0000 (Mon, 28 Sep 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1893-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1893-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1893");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-imapd-2.2, kolab-cyrus-imapd' package(s) announced via the DSA-1893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SIEVE component of cyrus-imapd and kolab-cyrus-imapd, the Cyrus mail system, is vulnerable to a buffer overflow when processing SIEVE scripts. This can be used to elevate privileges to the cyrus system user. An attacker who is able to install SIEVE scripts executed by the server is therefore able to read and modify arbitrary email messages on the system. The update introduced by DSA 1881-1 was incomplete and the issue has been given an additional CVE id due to its complexity.

For the oldstable distribution (etch), this problem has been fixed in version 2.2.13-10+etch4 for cyrus-imapd-2.2 and version 2.2.13-2+etch2 for kolab-cyrus-imapd.

For the stable distribution (lenny), this problem has been fixed in version 2.2.13-14+lenny3 for cyrus-imapd-2.2, version 2.2.13-5+lenny2 for kolab-cyrus-imapd.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.2.13-15 for cyrus-imapd-2.2, and will be fixed soon for kolab-cyrus-imapd.

We recommend that you upgrade your cyrus-imapd-2.2 and kolab-cyrus-imapd packages.");

  script_tag(name:"affected", value:"'cyrus-imapd-2.2, kolab-cyrus-imapd' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-admin", ver:"2.2.13-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-clients", ver:"2.2.13-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-common", ver:"2.2.13-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-imapd", ver:"2.2.13-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-pop3d", ver:"2.2.13-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-libcyrus-imap-perl", ver:"2.2.13-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-10+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-admin", ver:"2.2.13-5+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-clients", ver:"2.2.13-5+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-common", ver:"2.2.13-5+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-imapd", ver:"2.2.13-5+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-cyrus-pop3d", ver:"2.2.13-5+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolab-libcyrus-imap-perl", ver:"2.2.13-5+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-14+lenny3", rls:"DEB5"))) {
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
