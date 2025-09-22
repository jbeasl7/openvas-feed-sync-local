# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892441");
  script_cve_id("CVE-2018-1000671");
  script_tag(name:"creation_date", value:"2020-11-10 04:00:20 +0000 (Tue, 10 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-02 17:29:29 +0000 (Fri, 02 Nov 2018)");

  script_name("Debian: Security Advisory (DLA-2441-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2441-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2441-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sympa");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sympa' package(s) announced via the DLA-2441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A privilege escalation was discovered in Sympa, a modern mailing list manager. It is fixed when Sympa is used in conjunction with common MTAs (such as Exim or Postfix) by disabling a setuid executable, although no fix is currently available for all environments (such as sendmail). Additionally, an open-redirect vulnerability was discovered and fixed.

CVE-2020-26880

Sympa allows a local privilege escalation from the sympa user account to full root access by modifying the sympa.conf configuration file (which is owned by sympa) and parsing it through the setuid sympa_newaliases-wrapper executable.

CVE-2018-1000671

Sympa contains a CWE-601: URL Redirection to Untrusted Site ('Open Redirect') vulnerability in The referer parameter of the wwsympa.fcgi login action. that can result in Open redirection and reflected XSS via data URIs.

For Debian 9 stretch, these problems have been fixed in version 6.2.16~dfsg-3+deb9u4.

We recommend that you upgrade your sympa packages.

For the detailed security status of sympa please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sympa' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sympa", ver:"6.2.16~dfsg-3+deb9u4", rls:"DEB9"))) {
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
