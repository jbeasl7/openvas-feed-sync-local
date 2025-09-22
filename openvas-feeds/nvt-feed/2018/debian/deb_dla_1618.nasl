# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891618");
  script_cve_id("CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365", "CVE-2018-13139", "CVE-2018-19432", "CVE-2018-19661", "CVE-2018-19662");
  script_tag(name:"creation_date", value:"2018-12-27 23:00:00 +0000 (Thu, 27 Dec 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-24 17:22:57 +0000 (Fri, 24 Aug 2018)");

  script_name("Debian: Security Advisory (DLA-1618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1618-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1618-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsndfile' package(s) announced via the DLA-1618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in libsndfile, the library for reading and writing files containing sampled sound.

CVE-2017-8361

The flac_buffer_copy function (flac.c) is affected by a buffer overflow. This vulnerability might be leveraged by remote attackers to cause a denial of service, or possibly have unspecified other impact via a crafted audio file.

CVE-2017-8362

The flac_buffer_copy function (flac.c) is affected by an out-of-bounds read vulnerability. This flaw might be leveraged by remote attackers to cause a denial of service via a crafted audio file.

CVE-2017-8363

The flac_buffer_copy function (flac.c) is affected by a heap based OOB read vulnerability. This flaw might be leveraged by remote attackers to cause a denial of service via a crafted audio file.

CVE-2017-8365

The i2les_array function (pcm.c) is affected by a global buffer overflow. This vulnerability might be leveraged by remote attackers to cause a denial of service, or possibly have unspecified other impact via a crafted audio file.

CVE-2017-14245 / CVE-2017-14246 / CVE-2017-17456 / CVE-2017-17457 The d2alaw_array() and d2ulaw_array() functions (src/ulaw.c and src/alaw.c) are affected by an out-of-bounds read vulnerability. This flaw might be leveraged by remote attackers to cause denial of service or information disclosure via a crafted audio file.

CVE-2017-14634

The double64_init() function (double64.c) is affected by a divide-by-zero error. This vulnerability might be leveraged by remote attackers to cause denial of service via a crafted audio file.

CVE-2018-13139

The psf_memset function (common.c) is affected by a stack-based buffer overflow. This vulnerability might be leveraged by remote attackers to cause a denial of service, or possibly have unspecified other impact via a crafted audio file. The vulnerability can be triggered by the executable sndfile-deinterleave.

CVE-2018-19432

The sf_write_int function (src/sndfile.c) is affected by an out-of-bounds read vulnerability. This flaw might be leveraged by remote attackers to cause a denial of service via a crafted audio file.

CVE-2018-19661 / CVE-2018-19662 The i2alaw_array() and i2ulaw_array() functions (src/ulaw.c and src/alaw.c) are affected by an out-of-bounds read vulnerability. This flaw might be leveraged by remote attackers to cause denial of service or information disclosure via a crafted audio file.

For Debian 8 Jessie, these problems have been fixed in version 1.0.25-9.1+deb8u2.

We recommend that you upgrade your libsndfile packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.25-9.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1-dbg", ver:"1.0.25-9.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.25-9.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.25-9.1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sndfile-programs-dbg", ver:"1.0.25-9.1+deb8u2", rls:"DEB8"))) {
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
