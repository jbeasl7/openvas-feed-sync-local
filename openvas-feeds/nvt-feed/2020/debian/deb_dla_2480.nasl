# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892480");
  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_tag(name:"creation_date", value:"2020-12-05 04:00:17 +0000 (Sat, 05 Dec 2020)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 15:14:38 +0000 (Mon, 16 Nov 2020)");

  script_name("Debian: Security Advisory (DLA-2480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2480-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2480-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/salt");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'salt' package(s) announced via the DLA-2480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in salt.

CVE-2020-16846

An unauthenticated user with network access to the Salt API can use shell injections to run code on the Salt-API using the SSH client

CVE-2020-17490

When using the functions create_ca, create_csr, and create_self_signed_cert in the tls execution module, it would not ensure the key was created with the correct permissions.

CVE-2020-25592

Properly validate eauth credentials and tokens along with their Access Control Lists - ACLs. Prior to this change, eauth was not properly validated when calling Salt SSH via the salt-api. Any value for 'eauth' or 'token' would allow a user to bypass authentication and make calls to Salt SSH

For Debian 9 stretch, these problems have been fixed in version 2016.11.2+ds-1+deb9u6.

We recommend that you upgrade your salt packages.

For the detailed security status of salt please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'salt' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-cloud", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-doc", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-proxy", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"2016.11.2+ds-1+deb9u6", rls:"DEB9"))) {
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
