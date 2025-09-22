# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704747");
  script_cve_id("CVE-2020-24368");
  script_tag(name:"creation_date", value:"2020-08-25 03:00:15 +0000 (Tue, 25 Aug 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-25 19:28:15 +0000 (Tue, 25 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4747-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4747-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4747-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4747");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/icingaweb2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icingaweb2' package(s) announced via the DSA-4747-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A directory traversal vulnerability was discovered in Icinga Web 2, a web interface for Icinga, which could result in the disclosure of files readable by the process.

For the stable distribution (buster), this problem has been fixed in version 2.6.2-3+deb10u1.

We recommend that you upgrade your icingaweb2 packages.

For the detailed security status of icingaweb2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'icingaweb2' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icingacli", ver:"2.6.2-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icingaweb2", ver:"2.6.2-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icingaweb2-common", ver:"2.6.2-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icingaweb2-module-doc", ver:"2.6.2-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icingaweb2-module-monitoring", ver:"2.6.2-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-icinga", ver:"2.6.2-3+deb10u1", rls:"DEB10"))) {
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
