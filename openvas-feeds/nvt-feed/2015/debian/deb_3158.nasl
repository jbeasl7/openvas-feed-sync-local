# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703158");
  script_cve_id("CVE-2014-9274", "CVE-2014-9275");
  script_tag(name:"creation_date", value:"2015-02-08 23:00:00 +0000 (Sun, 08 Feb 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3158-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3158-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3158-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3158");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unrtf' package(s) announced via the DSA-3158-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michal Zalewski and Hanno Boeck discovered several vulnerabilities in unrtf, a RTF to other formats converter, leading to a denial of service (application crash) or, potentially, the execution of arbitrary code.

For the stable distribution (wheezy), these problems have been fixed in version 0.21.5-3~deb7u1. This update is based on a new upstream version of unrtf including additional bug fixes, new features and incompatible changes (especially PostScript support is dropped).

For the upcoming stable distribution (jessie) and the unstable distribution (sid), these problems have been fixed in version 0.21.5-2.

We recommend that you upgrade your unrtf packages.");

  script_tag(name:"affected", value:"'unrtf' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"unrtf", ver:"0.21.5-3~deb7u1", rls:"DEB7"))) {
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
