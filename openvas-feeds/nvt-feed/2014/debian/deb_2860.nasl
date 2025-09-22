# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702860");
  script_cve_id("CVE-2014-1921");
  script_tag(name:"creation_date", value:"2014-02-10 23:00:00 +0000 (Mon, 10 Feb 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2860-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2860-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2860-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2860");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'parcimonie' package(s) announced via the DSA-2860-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Holger Levsen discovered that parcimonie, a privacy-friendly helper to refresh a GnuPG keyring, is affected by a design problem that undermines the usefulness of this piece of software in the intended threat model.

When using parcimonie with a large keyring (1000 public keys or more), it would always sleep exactly ten minutes between two key fetches. This can probably be used by an adversary who can watch enough key fetches to correlate multiple key fetches with each other, which is what parcimonie aims at protecting against. Smaller keyrings are affected to a smaller degree. This problem is slightly mitigated when using a HKP(s) pool as the configured GnuPG keyserver.

For the stable distribution (wheezy), this problem has been fixed in version 0.7.1-1+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 0.8.1-1.

We recommend that you upgrade your parcimonie packages.");

  script_tag(name:"affected", value:"'parcimonie' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"parcimonie", ver:"0.7.1-1+deb7u1", rls:"DEB7"))) {
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
