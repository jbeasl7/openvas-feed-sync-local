# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63496");
  script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");
  script_tag(name:"creation_date", value:"2009-03-07 20:47:03 +0000 (Sat, 07 Mar 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1729-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1729-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1729-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1729");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gst-plugins-bad0.10' package(s) announced via the DSA-1729-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in gst-plugins-bad0.10, a collection of various GStreamer plugins. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0386

Tobias Klein discovered a buffer overflow in the quicktime stream demuxer (qtdemux), which could potentially lead to the execution of arbitrary code via crafted .mov files.

CVE-2009-0387

Tobias Klein discovered an array index error in the quicktime stream demuxer (qtdemux), which could potentially lead to the execution of arbitrary code via crafted .mov files.

CVE-2009-0397

Tobias Klein discovered a buffer overflow in the quicktime stream demuxer (qtdemux) similar to the issue reported in CVE-2009-0386, which could also lead to the execution of arbitrary code via crafted .mov files.

For the oldstable distribution (etch), these problems have been fixed in version 0.10.3-3.1+etch1.

For the stable distribution (lenny), these problems have been fixed in version 0.10.8-4.1~lenny1 of gst-plugins-good0.10, since the affected plugin has been moved there. The fix was already included in the lenny release.

For the unstable distribution (sid) and the testing distribution (squeeze), these problems have been fixed in version 0.10.8-4.1 of gst-plugins-good0.10.");

  script_tag(name:"affected", value:"'gst-plugins-bad0.10' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gstreamer0.10-plugins-bad", ver:"0.10.3-3.1+etch1", rls:"DEB4"))) {
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
