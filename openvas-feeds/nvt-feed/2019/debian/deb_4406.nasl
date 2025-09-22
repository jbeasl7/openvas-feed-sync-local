# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704406");
  script_cve_id("CVE-2019-0804");
  script_tag(name:"creation_date", value:"2019-03-11 23:00:00 +0000 (Mon, 11 Mar 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-10 12:56:09 +0000 (Wed, 10 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-4406-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4406-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4406-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4406");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/waagent");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'waagent' package(s) announced via the DSA-4406-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Francis McBratney discovered that the Windows Azure Linux Agent created swap files with world-readable permissions, resulting in information disclosure.

For the stable distribution (stretch), this problem has been fixed in version 2.2.18-3~deb9u2.

We recommend that you upgrade your waagent packages.

For the detailed security status of waagent please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'waagent' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"waagent", ver:"2.2.18-3~deb9u2", rls:"DEB9"))) {
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
