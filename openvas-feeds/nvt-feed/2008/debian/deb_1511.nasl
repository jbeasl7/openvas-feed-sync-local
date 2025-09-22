# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60496");
  script_cve_id("CVE-2007-4770", "CVE-2007-4771");
  script_tag(name:"creation_date", value:"2008-03-11 20:16:32 +0000 (Tue, 11 Mar 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1511-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1511-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1511-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1511");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icu' package(s) announced via the DSA-1511-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in libicu, International Components for Unicode, The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-4770

libicu in International Components for Unicode (ICU) 3.8.1 and earlier attempts to process backreferences to the nonexistent capture group zero (aka 0), which might allow context-dependent attackers to read from, or write to, out-of-bounds memory locations, related to corruption of REStackFrames.

CVE-2007-4771

Heap-based buffer overflow in the doInterval function in regexcmp.cpp in libicu in International Components for Unicode (ICU) 3.8.1 and earlier allows context-dependent attackers to cause a denial of service (memory consumption) and possibly have unspecified other impact via a regular expression that writes a large amount of data to the backtracking stack.

For the stable distribution (etch), these problems have been fixed in version 3.6-2etch1.

For the unstable distribution (sid), these problems have been fixed in version 3.8-6.

We recommend that you upgrade your libicu package.");

  script_tag(name:"affected", value:"'icu' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icu-doc", ver:"3.6-2etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu36", ver:"3.6-2etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu36-dev", ver:"3.6-2etch1", rls:"DEB4"))) {
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
