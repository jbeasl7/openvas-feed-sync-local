# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704169");
  script_cve_id("CVE-2018-1086");
  script_tag(name:"creation_date", value:"2018-04-10 22:00:00 +0000 (Tue, 10 Apr 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-17 15:54:44 +0000 (Thu, 17 May 2018)");

  script_name("Debian: Security Advisory (DSA-4169-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4169-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4169-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4169");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pcs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pcs' package(s) announced via the DSA-4169-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cedric Buissart from Red Hat discovered an information disclosure bug in pcs, a pacemaker command line interface and GUI. The REST interface normally doesn't allow passing --debug parameter to prevent information leak, but the check wasn't sufficient.

For the stable distribution (stretch), this problem has been fixed in version 0.9.155+dfsg-2+deb9u1.

We recommend that you upgrade your pcs packages.

For the detailed security status of pcs please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'pcs' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"pcs", ver:"0.9.155+dfsg-2+deb9u1", rls:"DEB9"))) {
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
