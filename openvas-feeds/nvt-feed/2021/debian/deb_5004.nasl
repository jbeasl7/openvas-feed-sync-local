# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705004");
  script_cve_id("CVE-2021-39139", "CVE-2021-39140", "CVE-2021-39141", "CVE-2021-39144", "CVE-2021-39145", "CVE-2021-39146", "CVE-2021-39147", "CVE-2021-39148", "CVE-2021-39149", "CVE-2021-39150", "CVE-2021-39151", "CVE-2021-39152", "CVE-2021-39153", "CVE-2021-39154");
  script_tag(name:"creation_date", value:"2021-11-14 02:00:35 +0000 (Sun, 14 Nov 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-26 20:43:25 +0000 (Thu, 26 Aug 2021)");

  script_name("Debian: Security Advisory (DSA-5004-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5004-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-5004-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5004");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxstream-java");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxstream-java' package(s) announced via the DSA-5004-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in XStream, a Java library to serialize objects to XML and back again.

These vulnerabilities may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream.

XStream itself sets up a whitelist by default now, i.e. it blocks all classes except those types it has explicit converters for. It used to have a blacklist by default, i.e. it tried to block all currently known critical classes of the Java runtime. Main reason for the blacklist were compatibility, it allowed to use newer versions of XStream as drop-in replacement. However, this approach has failed. A growing list of security reports has proven, that a blacklist is inherently unsafe, apart from the fact that types of 3rd libraries were not even considered. A blacklist scenario should be avoided in general, because it provides a false sense of security.

For the oldstable distribution (buster), these problems have been fixed in version 1.4.11.1-1+deb10u3.

For the stable distribution (bullseye), these problems have been fixed in version 1.4.15-3+deb11u1.

We recommend that you upgrade your libxstream-java packages.

For the detailed security status of libxstream-java please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian 10, Debian 11.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.15-3+deb11u1", rls:"DEB11"))) {
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
