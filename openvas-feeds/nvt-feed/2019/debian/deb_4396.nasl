# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704396");
  script_cve_id("CVE-2018-10855", "CVE-2018-10875", "CVE-2018-16837", "CVE-2018-16876", "CVE-2019-3828");
  script_tag(name:"creation_date", value:"2019-02-18 23:00:00 +0000 (Mon, 18 Feb 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-29 18:20:46 +0000 (Fri, 29 May 2020)");

  script_name("Debian: Security Advisory (DSA-4396-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4396-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4396-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4396");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ansible");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ansible' package(s) announced via the DSA-4396-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in Ansible, a configuration management, deployment, and task execution system:

CVE-2018-10855 / CVE-2018-16876 The no_log task flag wasn't honored, resulting in an information leak.

CVE-2018-10875

ansible.cfg was read from the current working directory.

CVE-2018-16837

The user module leaked parameters passed to ssh-keygen to the process environment.

CVE-2019-3828

The fetch module was susceptible to path traversal.

For the stable distribution (stretch), these problems have been fixed in version 2.2.1.0-2+deb9u1.

We recommend that you upgrade your ansible packages.

For the detailed security status of ansible please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ansible' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"2.2.1.0-2+deb9u1", rls:"DEB9"))) {
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
