# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891959");
  script_cve_id("CVE-2016-10894");
  script_tag(name:"creation_date", value:"2019-10-15 02:00:09 +0000 (Tue, 15 Oct 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-29 17:00:20 +0000 (Thu, 29 Aug 2019)");

  script_name("Debian: Security Advisory (DLA-1959-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1959-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1959-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xtrlock' package(s) announced via the DLA-1959-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that multitouch devices were not being disabled by the xtrlock screen locking utility.

xtrlock did not block multitouch events so an attacker could still input and thus control various programs such as Chromium, etc. via so-called 'multitouch' events including pan scrolling, 'pinch and zoom' or even being able to provide regular mouse clicks by depressing the touchpad once and then clicking with a secondary finger.

CVE-2016-10894

xtrlock through 2.10 does not block multitouch events. Consequently, an attacker at a locked screen can send input to (and thus control) various programs such as Chromium via events such as pan scrolling, 'pinch and zoom' gestures, or even regular mouse clicks (by depressing the touchpad once and then clicking with a different finger).

For Debian 8 Jessie, these problems have been fixed in version 2.6+deb8u1. However, this fix does not the situation where an attacker plugs in a multitouch device after the screen has been locked (more info).

We recommend that you upgrade your xtrlock packages pending a deeper fix.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'xtrlock' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"xtrlock", ver:"2.6+deb8u1", rls:"DEB8"))) {
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
