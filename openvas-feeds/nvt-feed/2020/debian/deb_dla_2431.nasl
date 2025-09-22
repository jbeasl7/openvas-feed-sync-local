# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892431");
  script_cve_id("CVE-2019-13224", "CVE-2019-16163", "CVE-2019-19012", "CVE-2019-19203", "CVE-2019-19204", "CVE-2019-19246");
  script_tag(name:"creation_date", value:"2020-11-05 04:00:12 +0000 (Thu, 05 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-19 19:06:51 +0000 (Tue, 19 Nov 2019)");

  script_name("Debian: Security Advisory (DLA-2431-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2431-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2431-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libonig");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libonig' package(s) announced via the DLA-2431-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Oniguruma regular expressions library, notably used in PHP mbstring.

CVE-2019-13224

A use-after-free in onig_new_deluxe() in regext.c allows attackers to potentially cause information disclosure, denial of service, or possibly code execution by providing a crafted regular expression. The attacker provides a pair of a regex pattern and a string, with a multi-byte encoding that gets handled by onig_new_deluxe().

CVE-2019-16163

Oniguruma allows Stack Exhaustion in regcomp.c because of recursion in regparse.c.

CVE-2019-19012

An integer overflow in the search_in_range function in regexec.c in Onigurama leads to an out-of-bounds read, in which the offset of this read is under the control of an attacker. (This only affects the 32-bit compiled version). Remote attackers can cause a denial-of-service or information disclosure, or possibly have unspecified other impact, via a crafted regular expression.

CVE-2019-19203

An issue was discovered in Oniguruma. In the function gb18030_mbc_enc_len in file gb18030.c, a UChar pointer is dereferenced without checking if it passed the end of the matched string. This leads to a heap-based buffer over-read.

CVE-2019-19204

An issue was discovered in Oniguruma. In the function fetch_interval_quantifier (formerly known as fetch_range_quantifier) in regparse.c, PFETCH is called without checking PEND. This leads to a heap-based buffer over-read.

CVE-2019-19246

Oniguruma has a heap-based buffer over-read in str_lower_case_match in regexec.c.

CVE-2020-26159

In Oniguruma an attacker able to supply a regular expression for compilation may be able to overflow a buffer by one byte in concat_opt_exact_str in src/regcomp.c

For Debian 9 stretch, these problems have been fixed in version 6.1.3-2+deb9u1.

We recommend that you upgrade your libonig packages.

For the detailed security status of libonig please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libonig' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libonig-dev", ver:"6.1.3-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libonig4", ver:"6.1.3-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libonig4-dbg", ver:"6.1.3-2+deb9u1", rls:"DEB9"))) {
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
