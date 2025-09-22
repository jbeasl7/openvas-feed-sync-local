# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891914");
  script_cve_id("CVE-2019-10181", "CVE-2019-10182", "CVE-2019-10185");
  script_tag(name:"creation_date", value:"2019-09-10 02:00:20 +0000 (Tue, 10 Sep 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-07 18:02:53 +0000 (Wed, 07 Aug 2019)");

  script_name("Debian: Security Advisory (DLA-1914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1914-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1914-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedtea-web' package(s) announced via the DLA-1914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were found in icedtea-web, an implementation of the Java Network Launching Protocol (JNLP).

CVE-2019-10181

It was found that in icedtea-web executable code could be injected in a JAR file without compromising the signature verification. An attacker could use this flaw to inject code in a trusted JAR. The code would be executed inside the sandbox.

CVE-2019-10182

It was found that icedtea-web did not properly sanitize paths from <jar/> elements in JNLP files. An attacker could trick a victim into running a specially crafted application and use this flaw to upload arbitrary files to arbitrary locations in the context of the user.

CVE-2019-10185

It was found that icedtea-web was vulnerable to a zip-slip attack during auto-extraction of a JAR file. An attacker could use this flaw to write files to arbitrary locations. This could also be used to replace the main running application and, possibly, break out of the sandbox.

For Debian 8 Jessie, these problems have been fixed in version 1.5.3-1+deb8u1.

We recommend that you upgrade your icedtea-web packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-plugin", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx-common", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-plugin", ver:"1.5.3-1+deb8u1", rls:"DEB8"))) {
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
