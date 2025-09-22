# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703953");
  script_cve_id("CVE-2017-12440");
  script_tag(name:"creation_date", value:"2017-08-22 22:00:00 +0000 (Tue, 22 Aug 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-31 19:15:11 +0000 (Thu, 31 Aug 2017)");

  script_name("Debian: Security Advisory (DSA-3953-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-3953-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3953-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3953");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'aodh' package(s) announced via the DSA-3953-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zane Bitter from Red Hat discovered a vulnerability in Aodh, the alarm engine for OpenStack. Aodh does not verify that the user creating the alarm is the trustor or has the same rights as the trustor, nor that the trust is for the same project as the alarm. The bug allows that an authenticated user without a Keystone token with knowledge of trust IDs to perform unspecified authenticated actions by adding alarm actions.

For the stable distribution (stretch), this problem has been fixed in version 3.0.0-4+deb9u1.

We recommend that you upgrade your aodh packages.");

  script_tag(name:"affected", value:"'aodh' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"aodh-api", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aodh-common", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aodh-doc", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aodh-evaluator", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aodh-expirer", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aodh-listener", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aodh-notifier", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-aodh", ver:"3.0.0-4+deb9u1", rls:"DEB9"))) {
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
