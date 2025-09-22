# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53342");
  script_cve_id("CVE-2003-0138", "CVE-2003-0139");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-273)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-273");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-273");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-273");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb4' package(s) announced via the DSA-273 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A cryptographic weakness in version 4 of the Kerberos protocol allows an attacker to use a chosen-plaintext attack to impersonate any principal in a realm. Additional cryptographic weaknesses in the krb4 implementation permit the use of cut-and-paste attacks to fabricate krb4 tickets for unauthorized client principals if triple-DES keys are used to key krb4 services. These attacks can subvert a site's entire Kerberos authentication infrastructure.

For the stable distribution (woody) this problem has been fixed in version 1.1-8-2.3.

For the old stable distribution (potato) this problem has been fixed in version 1.0-2.3.

For the unstable distribution (sid) this problem has been fixed in version 1.2.2-1.

We recommend that you upgrade your krb4 packages immediately.");

  script_tag(name:"affected", value:"'krb4' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-clients", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-clients-x", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-dev", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-dev-common", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-docs", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-kdc", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-kip", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-servers", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-servers-x", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-services", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-user", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth-x11", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kerberos4kth1", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libacl1-kerberos4kth", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm1-kerberos4kth", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdb-1-kerberos4kth", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb-1-kerberos4kth", ver:"1.1-8-2.3", rls:"DEB3.0"))) {
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
