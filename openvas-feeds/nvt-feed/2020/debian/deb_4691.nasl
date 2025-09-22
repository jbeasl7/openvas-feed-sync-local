# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704691");
  script_cve_id("CVE-2020-10995", "CVE-2020-12244");
  script_tag(name:"creation_date", value:"2020-05-23 03:00:06 +0000 (Sat, 23 May 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-20 14:27:39 +0000 (Wed, 20 May 2020)");

  script_name("Debian: Security Advisory (DSA-4691-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4691-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4691-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4691");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pdns-recursor");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns-recursor' package(s) announced via the DSA-4691-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in PDNS Recursor, a resolving name server, a traffic amplification attack against third party authoritative name servers (NXNSAttack) and insufficient validation of NXDOMAIN responses lacking an SOA.

The version of pdns-recursor in the oldstable distribution (stretch) is no longer supported. If these security issues affect your setup, you should upgrade to the stable distribution (buster).

For the stable distribution (buster), these problems have been fixed in version 4.1.11-1+deb10u1.

We recommend that you upgrade your pdns-recursor packages.

For the detailed security status of pdns-recursor please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'pdns-recursor' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"pdns-recursor", ver:"4.1.11-1+deb10u1", rls:"DEB10"))) {
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
