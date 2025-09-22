# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702705");
  script_cve_id("CVE-2013-2132");
  script_tag(name:"creation_date", value:"2013-06-09 22:00:00 +0000 (Sun, 09 Jun 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2705-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2705-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2705");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pymongo' package(s) announced via the DSA-2705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jibbers McGee discovered that PyMongo, a high-performance schema-free document-oriented data store, is prone to a denial-of-service vulnerability.

An attacker can remotely trigger a NULL pointer dereference causing MongoDB to crash.

The oldstable distribution (squeeze) is not affected by this issue.

For the stable distribution (wheezy), this problem has been fixed in version 2.2-4+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 2.5.2-1.

For the unstable distribution (sid), this problem has been fixed in version 2.5.2-1.

We recommend that you upgrade your pymongo packages.");

  script_tag(name:"affected", value:"'pymongo' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-bson", ver:"2.2-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-bson-ext", ver:"2.2-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-gridfs", ver:"2.2-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pymongo", ver:"2.2-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pymongo-doc", ver:"2.2-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pymongo-ext", ver:"2.2-4+deb7u1", rls:"DEB7"))) {
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
