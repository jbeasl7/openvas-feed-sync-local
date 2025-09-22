# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64640");
  script_cve_id("CVE-2009-2414", "CVE-2009-2416");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:04:10 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1861-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1861-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1861-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1861");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml' package(s) announced via the DSA-1861-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rauli Kaksonen, Tero Rontti and Jukka Taimisto discovered several vulnerabilities in libxml, a library for parsing and handling XML data files, which can lead to denial of service conditions or possibly arbitrary code execution in the application using the library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2416

An XML document with specially-crafted Notation or Enumeration attribute types in a DTD definition leads to the use of a pointers to memory areas which have already been freed.

CVE-2009-2414

Missing checks for the depth of ELEMENT DTD definitions when parsing child content can lead to extensive stack-growth due to a function recursion which can be triggered via a crafted XML document.

For the oldstable distribution (etch), this problem has been fixed in version 1.8.17-14+etch1.

The stable (lenny), testing (squeeze) and unstable (sid) distribution do not contain libxml anymore but libxml2 for which DSA-1859-1 has been released.

We recommend that you upgrade your libxml packages.");

  script_tag(name:"affected", value:"'libxml' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml-dev", ver:"1:1.8.17-14+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml1", ver:"1:1.8.17-14+etch1", rls:"DEB4"))) {
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
