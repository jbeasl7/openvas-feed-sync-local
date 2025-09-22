# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891705");
  script_cve_id("CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-15371");
  script_tag(name:"creation_date", value:"2019-03-05 23:00:00 +0000 (Tue, 05 Mar 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-27 14:45:39 +0000 (Fri, 27 Oct 2017)");

  script_name("Debian: Security Advisory (DLA-1705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1705-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1705-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sox' package(s) announced via the DLA-1705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in SoX (Sound eXchange), a sound processing program:

CVE-2017-11332

The startread function (wav.c) is affected by a divide-by-zero vulnerability when processing WAV file with zero channel count. This flaw might be leveraged by remote attackers using a crafted WAV file to perform denial of service (application crash).

CVE-2017-11358

The read_samples function (hcom.c) is affected by an invalid memory read vulnerability when processing HCOM files with invalid dictionaries. This flaw might be leveraged by remote attackers using a crafted HCOM file to perform denial of service (application crash).

CVE-2017-11359

The wavwritehdr function (wav.c) is affected by a divide-by-zero vulnerability when processing WAV files with invalid channel count over 16 bits. This flaw might be leveraged by remote attackers using a crafted WAV file to perform denial of service (application crash).

CVE-2017-15371

The sox_append_comment() function (formats.c) is vulnerable to a reachable assertion when processing FLAC files with metadata declaring more comments than provided. This flaw might be leveraged by remote attackers using crafted FLAC data to perform denial of service (application crash).

For Debian 8 Jessie, these problems have been fixed in version 14.4.1-5+deb8u3.

We recommend that you upgrade your sox packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sox' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsox-dev", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-all", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-alsa", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-ao", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-base", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-mp3", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-oss", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-pulse", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox2", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.1-5+deb8u3", rls:"DEB8"))) {
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
