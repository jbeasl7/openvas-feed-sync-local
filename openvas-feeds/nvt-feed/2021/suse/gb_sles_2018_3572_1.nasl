# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3572.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3572-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183572-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998183");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004814.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_nss' package(s) announced via the SUSE-SU-2018:3572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_nss fixes the following issues:

Due to the update of mozilla-nss apache2-mod_nss needs to be updated to change to the SQLite certificate database, which is now the default (bsc#1108771).
Because of that this update is tagged as security, to reach customers that only install security updates.

Other changes contained:

- Require minimal NSS version of 3.25 because of SSLv2 changes (bsc#993642)
- Add support for SHA384 TLS ciphers (bsc#863035)
- Remove deprecated NSSSessionCacheTimeout option from mod_nss.conf.in (bsc#998176)
- Change ownership of the gencert generated NSS database so apache can read it (bsc#998180)
- Use correct configuration path in mod_nss.conf.in (bsc#996282)
- Generate dummy certificates if there aren't any in mod_nss.d (bsc#998183)");

  script_tag(name:"affected", value:"'apache2-mod_nss' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_nss", rpm:"apache2-mod_nss~1.0.14~10.17.2", rls:"SLES12.0"))) {
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
