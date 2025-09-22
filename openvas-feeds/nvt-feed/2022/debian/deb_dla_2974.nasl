# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892974");
  script_cve_id("CVE-2022-25308", "CVE-2022-25309", "CVE-2022-25310");
  script_tag(name:"creation_date", value:"2022-04-15 01:00:09 +0000 (Fri, 15 Apr 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 14:49:57 +0000 (Thu, 08 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-2974-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2974-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2974-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/fribidi");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fribidi' package(s) announced via the DLA-2974-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in fribidi, a free Implementation of the Unicode BiDi algorithm. The issues are related to stack-buffer-overflow, heap-buffer-overflow, and a SEGV.

CVE-2022-25308

stack-buffer-overflow issue in main()

CVE-2022-25309

heap-buffer-overflow issue in fribidi_cap_rtl_to_unicode()

CVE-2022-25310

SEGV issue in fribidi_remove_bidi_marks()

For Debian 9 stretch, these problems have been fixed in version 0.19.7-1+deb9u2.

We recommend that you upgrade your fribidi packages.

For the detailed security status of fribidi please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'fribidi' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfribidi-bin", ver:"0.19.7-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfribidi-dev", ver:"0.19.7-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfribidi0", ver:"0.19.7-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfribidi0-udeb", ver:"0.19.7-1+deb9u2", rls:"DEB9"))) {
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
