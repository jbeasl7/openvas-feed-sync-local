# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704791");
  script_cve_id("CVE-2020-25654");
  script_tag(name:"creation_date", value:"2020-11-14 04:00:04 +0000 (Sat, 14 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-04 18:40:34 +0000 (Fri, 04 Dec 2020)");

  script_name("Debian: Security Advisory (DSA-4791-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4791-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4791-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4791");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pacemaker");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pacemaker' package(s) announced via the DSA-4791-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ken Gaillot discovered a vulnerability in the Pacemaker cluster resource manager: If ACLs were configured for users in the haclient group, the ACL restrictions could be bypassed via unrestricted IPC communication, resulting in cluster-wide arbitrary code execution with root privileges.

If the enable-acl cluster option isn't enabled, members of the haclient group can modify Pacemaker's Cluster Information Base without restriction, which already gives them these capabilities, so there is no additional exposure in such a setup.

For the stable distribution (buster), this problem has been fixed in version 2.0.1-5+deb10u1.

We recommend that you upgrade your pacemaker packages.

For the detailed security status of pacemaker please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'pacemaker' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcib-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcib27", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrmcluster-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrmcluster29", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrmcommon-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrmcommon34", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrmservice-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcrmservice28", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblrmd-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblrmd28", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpe-rules26", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpe-status28", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpengine-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpengine27", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstonithd-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstonithd26", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtransitioner25", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker-cli-utils", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker-common", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker-dev", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker-doc", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker-remote", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pacemaker-resource-agents", ver:"2.0.1-5+deb10u1", rls:"DEB10"))) {
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
