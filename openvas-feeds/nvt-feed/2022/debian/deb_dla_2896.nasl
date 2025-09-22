# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892896");
  script_cve_id("CVE-2022-21699");
  script_tag(name:"creation_date", value:"2022-01-25 02:00:03 +0000 (Tue, 25 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-26 17:53:23 +0000 (Wed, 26 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-2896-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2896-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2896-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ipython' package(s) announced via the DLA-2896-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential arbitrary code execution vulnerability in IPython, the interactive Python shell.

This issue stemmed from IPython executing untrusted files in the current working directory. According to upstream:

Almost all versions of IPython looks for configuration and profiles in current working directory. Since IPython was developed before pip and environments existed, it was used a convenient way to load code/packages in a project dependent way.

In 2022, it is not necessary anymore, and can lead to confusing behavior where for example cloning a repository and starting IPython or loading a notebook from any Jupyter-Compatible interface that has ipython set as a kernel can lead to code execution.

To address this problem, the current working directory is no longer searched for profiles or configuration files.

CVE-2022-21699

IPython (Interactive Python) is a command shell for interactive computing in multiple programming languages, originally developed for the Python programming language. Affected versions are subject to an arbitrary code execution vulnerability achieved by not properly managing cross user temporary files. This vulnerability allows one user to run code as another on the same machine. All users are advised to upgrade.

For Debian 9 Stretch, these problems have been fixed in version 5.1.0-3+deb9u1.

We recommend that you upgrade your ipython packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ipython' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ipython", ver:"5.1.0-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipython3", ver:"5.1.0-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ipython", ver:"5.1.0-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ipython-doc", ver:"5.1.0-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ipython", ver:"5.1.0-3+deb9u1", rls:"DEB9"))) {
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
