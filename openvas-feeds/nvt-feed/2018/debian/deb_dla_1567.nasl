# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891567");
  script_cve_id("CVE-2018-18718");
  script_tag(name:"creation_date", value:"2018-11-05 23:00:00 +0000 (Mon, 05 Nov 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-07 20:29:43 +0000 (Fri, 07 Dec 2018)");

  script_name("Debian: Security Advisory (DLA-1567-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1567-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1567-1");
  script_xref(name:"URL", value:"https://gitlab.gnome.org/GNOME/gthumb/issues/18");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gthumb' package(s) announced via the DLA-1567-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-18718 - CWE-415: Double Free The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations. There is a suspected double-free bug with static void add_themes_from_dir() dlg-contact-sheet.c. This method involves two successive calls of g_free(buffer) (line 354 and 373), and is likely to cause double-free of the buffer. One possible fix could be directly assigning the buffer to NULL after the first call of g_free(buffer). Thanks Tianjun Wu [link moved to references]

For Debian 8 Jessie, this problem has been fixed in version 3:3.3.1-2.1+deb8u1

We recommend that you upgrade your gthumb packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gthumb' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gthumb", ver:"3:3.3.1-2.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gthumb-data", ver:"3:3.3.1-2.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gthumb-dbg", ver:"3:3.3.1-2.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gthumb-dev", ver:"3:3.3.1-2.1+deb8u1", rls:"DEB8"))) {
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
