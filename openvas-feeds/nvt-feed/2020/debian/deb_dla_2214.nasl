# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892214");
  script_cve_id("CVE-2016-6328", "CVE-2017-7544", "CVE-2018-20030", "CVE-2020-0093", "CVE-2020-12767");
  script_tag(name:"creation_date", value:"2020-05-19 03:00:16 +0000 (Tue, 19 May 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-21 15:59:01 +0000 (Thu, 21 Feb 2019)");

  script_name("Debian: Security Advisory (DLA-2214-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2214-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2214-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libexif' package(s) announced via the DLA-2214-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various vulnerabilities have been addressed in libexif, a library to parse EXIF metadata files.

CVE-2016-6328

An integer overflow when parsing the MNOTE entry data of the input file had been found. This could have caused Denial-of-Service (DoS) and Information Disclosure (disclosing some critical heap chunk metadata, even other applications' private data).

CVE-2017-7544

libexif had been vulnerable to out-of-bounds heap read vulnerability in exif_data_save_data_entry function in libexif/exif-data.c caused by improper length computation of the allocated data of an ExifMnote entry which could have caused denial-of-service or possibly information disclosure.

CVE-2018-20030

An error when processing the EXIF_IFD_INTEROPERABILITY and EXIF_IFD_EXIF tags within libexif version could have been exploited to exhaust available CPU resources.

CVE-2020-0093

In exif_data_save_data_entry of exif-data.c, there was a possible out of bounds read due to a missing bounds check. This could have lead to local information disclosure with no additional execution privileges needed. User interaction was needed for exploitation.

CVE-2020-12767

libexif had a divide-by-zero error in exif_entry_get_value in exif-entry.c

For Debian 8 Jessie, these problems have been fixed in version 0.6.21-2+deb8u2.

We recommend that you upgrade your libexif packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libexif' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libexif-dev", ver:"0.6.21-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexif12", ver:"0.6.21-2+deb8u2", rls:"DEB8"))) {
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
