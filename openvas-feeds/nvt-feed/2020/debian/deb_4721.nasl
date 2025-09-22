# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704721");
  script_cve_id("CVE-2020-10663", "CVE-2020-10933");
  script_tag(name:"creation_date", value:"2020-07-09 03:00:06 +0000 (Thu, 09 Jul 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-08 15:37:13 +0000 (Fri, 08 May 2020)");

  script_name("Debian: Security Advisory (DSA-4721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4721-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4721-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4721");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby2.5");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.5' package(s) announced via the DSA-4721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Ruby language.

CVE-2020-10663

Jeremy Evans reported an unsafe object creation vulnerability in the json gem bundled with Ruby. When parsing certain JSON documents, the json gem can be coerced into creating arbitrary objects in the target system.

CVE-2020-10933

Samuel Williams reported a flaw in the socket library which may lead to exposure of possibly sensitive data from the interpreter.

For the stable distribution (buster), these problems have been fixed in version 2.5.5-3+deb10u2.

We recommend that you upgrade your ruby2.5 packages.

For the detailed security status of ruby2.5 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby2.5' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.5", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-dev", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-doc", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
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
