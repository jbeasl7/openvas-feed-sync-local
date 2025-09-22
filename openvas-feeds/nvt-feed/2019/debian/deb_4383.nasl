# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704383");
  script_cve_id("CVE-2018-15126", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024", "CVE-2018-21247", "CVE-2018-6307");
  script_tag(name:"creation_date", value:"2019-02-02 23:00:00 +0000 (Sat, 02 Feb 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-07 21:11:03 +0000 (Mon, 07 Jan 2019)");

  script_name("Debian: Security Advisory (DSA-4383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4383-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4383-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4383");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libvncserver");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvncserver' package(s) announced via the DSA-4383-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pavel Cheremushkin discovered several vulnerabilities in libvncserver, a library to implement VNC server/client functionalities, which might result in the execution of arbitrary code, denial of service or information disclosure.

For the stable distribution (stretch), these problems have been fixed in version 0.9.11+dfsg-1.3~deb9u1.

We recommend that you upgrade your libvncserver packages.

For the detailed security status of libvncserver please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient1", ver:"0.9.11+dfsg-1.3~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient1-dbg", ver:"0.9.11+dfsg-1.3~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver-config", ver:"0.9.11+dfsg-1.3~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver-dev", ver:"0.9.11+dfsg-1.3~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver1", ver:"0.9.11+dfsg-1.3~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver1-dbg", ver:"0.9.11+dfsg-1.3~deb9u1", rls:"DEB9"))) {
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
