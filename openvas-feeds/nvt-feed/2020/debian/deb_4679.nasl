# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704679");
  script_cve_id("CVE-2020-12689", "CVE-2020-12690", "CVE-2020-12691", "CVE-2020-12692");
  script_tag(name:"creation_date", value:"2020-05-08 03:00:14 +0000 (Fri, 08 May 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-11 18:58:56 +0000 (Mon, 11 May 2020)");

  script_name("Debian: Security Advisory (DSA-4679-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4679-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4679-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4679");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/keystone");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'keystone' package(s) announced via the DSA-4679-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the EC2 credentials API of Keystone, the OpenStack identity service: Any user authenticated within a limited scope (trust/oauth/application credential) could create an EC2 credential with an escalated permission, such as obtaining admin while the user is on a limited viewer role.

For the stable distribution (buster), this problem has been fixed in version 2:14.2.0-0+deb10u1.

We recommend that you upgrade your keystone packages.

For the detailed security status of keystone please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'keystone' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"keystone", ver:"2:14.2.0-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"keystone-doc", ver:"2:14.2.0-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-keystone", ver:"2:14.2.0-0+deb10u1", rls:"DEB10"))) {
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
