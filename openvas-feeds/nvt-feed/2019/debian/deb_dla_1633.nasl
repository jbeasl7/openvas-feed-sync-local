# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891633");
  script_cve_id("CVE-2017-10989", "CVE-2017-2518", "CVE-2017-2519", "CVE-2017-2520", "CVE-2018-8740");
  script_tag(name:"creation_date", value:"2019-01-13 23:00:00 +0000 (Sun, 13 Jan 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-31 00:47:50 +0000 (Wed, 31 May 2017)");

  script_name("Debian: Security Advisory (DLA-1633-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1633-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1633-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sqlite3' package(s) announced via the DLA-1633-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were corrected in SQLite, an SQL database engine.

CVE-2017-2518

A use-after-free bug in the query optimizer may cause a buffer overflow and application crash via a crafted SQL statement.

CVE-2017-2519

Insufficient size of the reference count on Table objects could lead to a denial-of-service or arbitrary code execution.

CVE-2017-2520

The sqlite3_value_text() interface returned a buffer that was not large enough to hold the complete string plus zero terminator when the input was a zeroblob. This could lead to arbitrary code execution or a denial-of-service.

CVE-2017-10989

SQLite mishandles undersized RTree blobs in a crafted database leading to a heap-based buffer over-read or possibly unspecified other impact.

CVE-2018-8740

Databases whose schema is corrupted using a CREATE TABLE AS statement could cause a NULL pointer dereference.

For Debian 8 Jessie, these problems have been fixed in version 3.8.7.1-1+deb8u4.

We recommend that you upgrade your sqlite3 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"lemon", ver:"3.8.7.1-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.8.7.1-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0-dbg", ver:"3.8.7.1-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-dev", ver:"3.8.7.1-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-tcl", ver:"3.8.7.1-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.8.7.1-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqlite3-doc", ver:"3.8.7.1-1+deb8u4", rls:"DEB8"))) {
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
