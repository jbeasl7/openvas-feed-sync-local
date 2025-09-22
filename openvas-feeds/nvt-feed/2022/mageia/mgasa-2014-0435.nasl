# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0435");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0435)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0435");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0435.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14347");
  script_xref(name:"URL", value:"https://www.prolexic.com/kcresources/prolexic-threat-advisories/prolexic-threat-advisory-ssdp-reflection-ddos-attacks/ssdp-reflection-attacks-cybersecurity-locked.html");
  script_xref(name:"URL", value:"https://www.prolexic.com/knowledge-center-ddos-threat-advisory-ssdp-reflection-ddos-attacks.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mythtv, mythtv-mythweb' package(s) announced via the MGASA-2014-0435 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated MythTV packages to harden against SSDP reflection attacks

MythTV's UPNP component was susceptible to SSDP reflection attacks
and has been hardened to disallow SSDP device discovery from non-local
addresses as mitigation.

Additionally, a popular schedules retrieval service, Schedules Direct,
will deprecate the old URL used by MythTV to retrieve metadata on 1st
November 2015. This build of MythTV also updates the URL for this
service for continued operation going forward.");

  script_tag(name:"affected", value:"'mythtv, mythtv-mythweb' package(s) on Mageia 3, Mageia 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64myth-devel", rpm:"lib64myth-devel~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth-devel", rpm:"lib64myth-devel~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth0.27", rpm:"lib64myth0.27~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth0.27", rpm:"lib64myth0.27~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth-devel", rpm:"libmyth-devel~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth-devel", rpm:"libmyth-devel~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth0.27", rpm:"libmyth0.27~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth0.27", rpm:"libmyth0.27~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv", rpm:"mythtv~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv", rpm:"mythtv~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-backend", rpm:"mythtv-backend~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-backend", rpm:"mythtv-backend~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-common", rpm:"mythtv-common~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-common", rpm:"mythtv-common~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-doc", rpm:"mythtv-doc~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-doc", rpm:"mythtv-doc~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-frontend", rpm:"mythtv-frontend~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-frontend", rpm:"mythtv-frontend~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-mythweb", rpm:"mythtv-mythweb~0.27.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-archive", rpm:"mythtv-plugin-archive~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-archive", rpm:"mythtv-plugin-archive~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-browser", rpm:"mythtv-plugin-browser~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-browser", rpm:"mythtv-plugin-browser~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-gallery", rpm:"mythtv-plugin-gallery~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-gallery", rpm:"mythtv-plugin-gallery~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-game", rpm:"mythtv-plugin-game~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-game", rpm:"mythtv-plugin-game~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-music", rpm:"mythtv-plugin-music~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-music", rpm:"mythtv-plugin-music~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-netvision", rpm:"mythtv-plugin-netvision~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-netvision", rpm:"mythtv-plugin-netvision~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-news", rpm:"mythtv-plugin-news~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-news", rpm:"mythtv-plugin-news~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-weather", rpm:"mythtv-plugin-weather~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-weather", rpm:"mythtv-plugin-weather~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-zoneminder", rpm:"mythtv-plugin-zoneminder~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-zoneminder", rpm:"mythtv-plugin-zoneminder~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-setup", rpm:"mythtv-setup~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-setup", rpm:"mythtv-setup~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-themes-base", rpm:"mythtv-themes-base~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-themes-base", rpm:"mythtv-themes-base~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MythTV", rpm:"perl-MythTV~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MythTV", rpm:"perl-MythTV~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mythtv", rpm:"php-mythtv~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mythtv", rpm:"php-mythtv~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-mythtv", rpm:"python-mythtv~0.27.4~20141022.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-mythtv", rpm:"python-mythtv~0.27.4~20141022.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64myth-devel", rpm:"lib64myth-devel~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth-devel", rpm:"lib64myth-devel~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth0.27", rpm:"lib64myth0.27~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth0.27", rpm:"lib64myth0.27~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth-devel", rpm:"libmyth-devel~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth-devel", rpm:"libmyth-devel~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth0.27", rpm:"libmyth0.27~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth0.27", rpm:"libmyth0.27~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv", rpm:"mythtv~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv", rpm:"mythtv~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-backend", rpm:"mythtv-backend~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-backend", rpm:"mythtv-backend~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-common", rpm:"mythtv-common~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-common", rpm:"mythtv-common~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-doc", rpm:"mythtv-doc~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-doc", rpm:"mythtv-doc~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-frontend", rpm:"mythtv-frontend~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-frontend", rpm:"mythtv-frontend~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-mythweb", rpm:"mythtv-mythweb~0.27.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-archive", rpm:"mythtv-plugin-archive~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-archive", rpm:"mythtv-plugin-archive~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-browser", rpm:"mythtv-plugin-browser~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-browser", rpm:"mythtv-plugin-browser~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-gallery", rpm:"mythtv-plugin-gallery~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-gallery", rpm:"mythtv-plugin-gallery~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-game", rpm:"mythtv-plugin-game~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-game", rpm:"mythtv-plugin-game~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-music", rpm:"mythtv-plugin-music~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-music", rpm:"mythtv-plugin-music~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-netvision", rpm:"mythtv-plugin-netvision~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-netvision", rpm:"mythtv-plugin-netvision~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-news", rpm:"mythtv-plugin-news~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-news", rpm:"mythtv-plugin-news~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-weather", rpm:"mythtv-plugin-weather~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-weather", rpm:"mythtv-plugin-weather~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-zoneminder", rpm:"mythtv-plugin-zoneminder~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-zoneminder", rpm:"mythtv-plugin-zoneminder~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-setup", rpm:"mythtv-setup~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-setup", rpm:"mythtv-setup~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-themes-base", rpm:"mythtv-themes-base~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-themes-base", rpm:"mythtv-themes-base~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MythTV", rpm:"perl-MythTV~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MythTV", rpm:"perl-MythTV~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mythtv", rpm:"php-mythtv~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mythtv", rpm:"php-mythtv~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-mythtv", rpm:"python-mythtv~0.27.4~20141022.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-mythtv", rpm:"python-mythtv~0.27.4~20141022.1.mga4.tainted", rls:"MAGEIA4"))) {
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
