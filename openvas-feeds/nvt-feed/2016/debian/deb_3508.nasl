# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703508");
  script_cve_id("CVE-2016-1577", "CVE-2016-2089", "CVE-2016-2116");
  script_tag(name:"creation_date", value:"2016-03-05 23:00:00 +0000 (Sat, 05 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 15:37:18 +0000 (Thu, 14 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3508-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3508-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3508-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3508");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jasper' package(s) announced via the DSA-3508-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in JasPer, a library for manipulating JPEG-2000 files. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-1577

Jacob Baines discovered a double-free flaw in the jas_iccattrval_destroy function. A remote attacker could exploit this flaw to cause an application using the JasPer library to crash, or potentially, to execute arbitrary code with the privileges of the user running the application.

CVE-2016-2089

The Qihoo 360 Codesafe Team discovered a NULL pointer dereference flaw within the jas_matrix_clip function. A remote attacker could exploit this flaw to cause an application using the JasPer library to crash, resulting in a denial-of-service.

CVE-2016-2116

Tyler Hicks discovered a memory leak flaw in the jas_iccprof_createfrombuf function. A remote attacker could exploit this flaw to cause the JasPer library to consume memory, resulting in a denial-of-service.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.900.1-13+deb7u4.

For the stable distribution (jessie), these problems have been fixed in version 1.900.1-debian1-2.4+deb8u1.

We recommend that you upgrade your jasper packages.");

  script_tag(name:"affected", value:"'jasper' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-13+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-13+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-13+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-debian1-2.4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-debian1-2.4+deb8u1+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-debian1-2.4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-debian1-2.4+deb8u1+b1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-debian1-2.4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-debian1-2.4+deb8u1+b1", rls:"DEB8"))) {
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
