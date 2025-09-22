# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893164");
  script_cve_id("CVE-2020-24583", "CVE-2020-24584", "CVE-2021-23336", "CVE-2021-3281", "CVE-2022-34265");
  script_tag(name:"creation_date", value:"2022-10-30 02:00:18 +0000 (Sun, 30 Oct 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 15:39:14 +0000 (Wed, 13 Jul 2022)");

  script_name("Debian: Security Advisory (DLA-3164-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3164-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3164-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DLA-3164-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Django, a popular Python-based web development framework:

CVE-2020-24583: Fix incorrect permissions on intermediate-level directories on Python 3.7+. FILE_UPLOAD_DIRECTORY_PERMISSIONS mode was not applied to intermediate-level directories created in the process of uploading files and to intermediate-level collected static directories when using the collectstatic management command. You should review and manually fix permissions on existing intermediate-level directories.

CVE-2020-24584: Correct permission escalation vulnerability in intermediate-level directories of the file system cache. On Python 3.7 and above, the intermediate-level directories of the file system cache had the system's standard umask rather than 0o077 (no group or others permissions).

CVE-2021-3281: Fix a potential directory-traversal exploit via archive.extract(). The django.utils.archive.extract() function, used by startapp --template and startproject --template, allowed directory traversal via an archive with absolute paths or relative paths with dot segments.

CVE-2021-23336: Prevent a web cache poisoning attack via 'parameter cloaking'. Django contains a copy of urllib.parse.parse_qsl() which was added to backport some security fixes. A further security fix has been issued recently such that parse_qsl() no longer allows using ',' as a query parameter separator by default.

CVE-2022-34265: The Trunc() and Extract() database functions were subject to a potential SQL injection attack if untrusted data was used as a value for the 'kind' or 'lookup_name' parameters. Applications that constrain the choice to a known safe list were unaffected.

For Debian 10 Buster, these problems have been fixed in version 1:1.11.29-1+deb10u2.

We recommend that you upgrade your python-django packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1:1.11.29-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-common", ver:"1:1.11.29-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1:1.11.29-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.11.29-1+deb10u2", rls:"DEB10"))) {
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
