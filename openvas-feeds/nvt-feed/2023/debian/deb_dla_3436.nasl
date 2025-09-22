# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3436");
  script_cve_id("CVE-2018-16838", "CVE-2019-3811", "CVE-2021-3621", "CVE-2022-4254");
  script_tag(name:"creation_date", value:"2023-05-30 04:22:27 +0000 (Tue, 30 May 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-09 13:41:12 +0000 (Thu, 09 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-3436-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3436-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3436-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sssd");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sssd' package(s) announced via the DLA-3436-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in sssd, a set of daemons to manage access to remote directories and authentication mechanisms, which could lead to privilege escalation.

CVE-2018-16838

It was discovered that when the Group Policy Objects (GPO) are not readable by SSSD due to a too strict permission settings on the server side, SSSD allows all authenticated users to login instead of denying access.

A new boolean setting ad_gpo_ignore_unreadable (defaulting to False) is introduced for environments where attributes in the groupPolicyContainer are not readable and changing the permissions on the GPO objects is not possible or desirable. See sssd-ad(5).

CVE-2019-3811

It was discovered that if a user was configured with no home directory set, then sssd(8) returns / (i.e., the root directory) instead of the empty string (meaning no home directory). This could impact services that restrict the user's filesystem access to within their home directory through chroot() or similar.

CVE-2021-3621

It was discovered that the sssctl(8) command was vulnerable to shell command injection via the logs-fetch and cache-expire subcommands.

This flaw could allows an attacker to trick the root user into running a specially crafted sssctl(8) command, such as via sudo, in order to gain root privileges.

CVE-2022-4254

It was discovered that libsss_certmap failed to sanitize certificate data used in LDAP filters.

PKINIT enables a client to authenticate to the KDC using an X.509 certificate and the corresponding private key, rather than a passphrase or keytab. Mapping rules are used in order to map the certificate presented during a PKINIT authentication request to the corresponding principal. However the mapping filter was found to be vulnerable to LDAP filter injection. As the search result is be influenced by values in the certificate, which may be attacker controlled, this flaw could allow an attacker to gain control of the admin account, leading to full domain takeover.

For Debian 10 buster, these problems have been fixed in version 1.16.3-3.2+deb10u1.

We recommend that you upgrade your sssd packages.

For the detailed security status of sssd please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sssd' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libipa-hbac-dev", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libipa-hbac0", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-sss", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-sss", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-certmap-dev", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-certmap0", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-idmap-dev", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-idmap0", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-nss-idmap-dev", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-nss-idmap0", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-simpleifp-dev", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-simpleifp0", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-sudo", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient-sssd", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient-sssd-dev", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libipa-hbac", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libsss-nss-idmap", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-sss", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libipa-hbac", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libsss-nss-idmap", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-sss", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ad", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ad-common", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-common", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-dbus", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ipa", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-kcm", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-krb5", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-krb5-common", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ldap", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-proxy", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-tools", ver:"1.16.3-3.2+deb10u1", rls:"DEB10"))) {
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
