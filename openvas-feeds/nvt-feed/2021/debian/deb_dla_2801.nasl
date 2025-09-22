# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892801");
  script_cve_id("CVE-2017-9525", "CVE-2019-9704", "CVE-2019-9705", "CVE-2019-9706");
  script_tag(name:"creation_date", value:"2021-10-31 02:00:24 +0000 (Sun, 31 Oct 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 18:44:58 +0000 (Thu, 16 Dec 2021)");

  script_name("Debian: Security Advisory (DLA-2801-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2801-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2801-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cron");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cron' package(s) announced via the DLA-2801-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security problems have been fixed in the cron daemon.

CVE-2017-9525

Fix group crontab to root escalation via postinst.

CVE-2019-9704

A very large crontab created by a user could crash the daemon.

CVE-2019-9705

Enforce maximum crontab line count of 10000 to prevent a malicious user from creating an excessivly large crontab.

CVE-2019-9706

Fix for possible DoS by use-after-free.

Additionally, a bypass of /etc/cron.{allow,deny} on failure to open has been fixed. If these files exist, then they must be readable by the user executing crontab(1). Users will now be denied by default if they aren't.

For Debian 9 stretch, these problems have been fixed in version 3.0pl1-128+deb9u2.

We recommend that you upgrade your cron packages.

For the detailed security status of cron please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'cron' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cron", ver:"3.0pl1-128+deb9u2", rls:"DEB9"))) {
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
