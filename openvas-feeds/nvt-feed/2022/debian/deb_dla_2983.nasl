# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892983");
  script_cve_id("CVE-2018-10753", "CVE-2018-10771", "CVE-2019-1010069", "CVE-2021-32434", "CVE-2021-32435", "CVE-2021-32436");
  script_tag(name:"creation_date", value:"2022-04-18 01:00:10 +0000 (Mon, 18 Apr 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-12 17:52:16 +0000 (Tue, 12 Jun 2018)");

  script_name("Debian: Security Advisory (DLA-2983-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2983-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2983-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/abcm2ps");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'abcm2ps' package(s) announced via the DLA-2983-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in abcm2ps: program which translates ABC music description files to PostScript.

CVE-2018-10753

Stack-based buffer overflow in the delayed_output function in music.c allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.

CVE-2018-10771

Stack-based buffer overflow in the get_key function in parse.c allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.

CVE-2019-1010069

Incorrect access control allows attackers to cause a denial of service via a crafted file.

CVE-2021-32434

Array overflow when wrong duration in voice overlay.

CVE-2021-32435

Stack-based buffer overflow in the function get_key in parse.c allows remote attackers to cause a senial of service (DoS) via unspecified vectors.

CVE-2021-32436

Out-of-bounds read in the function write_title() in subs.c allows remote attackers to cause a denial of service via unspecified vectors.

For Debian 9 stretch, these problems have been fixed in version 7.8.9-1+deb9u1.

We recommend that you upgrade your abcm2ps packages.

For the detailed security status of abcm2ps please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'abcm2ps' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"abcm2ps", ver:"7.8.9-1+deb9u1", rls:"DEB9"))) {
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
