# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123062");
  script_cve_id("CVE-2014-9680");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Oracle: Security Advisory (ELSA-2015-1409)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1409");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1409.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the ELSA-2015-1409 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.8.6p3-19]
- RHEL-6.7 erratum
 - modified the authlogicfix patch to fix #1144448
 - fixed a bug in the ldapusermatchfix patch
 Resolves: rhbz#1144448
 Resolves: rhbz#1142122

[1.8.6p3-18]
- RHEL-6.7 erratum
 - fixed the mantypos-ldap.patch
 Resolves: rhbz#1138267

[1.8.6p3-17]
- RHEL-6.7 erratum
 - added patch for CVE-2014-9680
 - added BuildRequires for tzdata
 Resolves: rhbz#1200253

[1.8.6p3-16]
- RHEL-6.7 erratum
 - added zlib-devel build required to enable zlib compression support
 - fixed two typos in the sudoers.ldap man page
 - fixed a hang when duplicate nss entries are specified in nsswitch.conf
 - SSSD: implemented sorting of the result entries according to the
 sudoOrder attribute
 - LDAP: fixed logic handling the computation of the 'user matched' flag
 - fixed restoring of the SIGPIPE signal in the tgetpass function
 - fixed listpw, verifypw + authenticate option logic in LDAP/SSSD
 Resolves: rhbz#1106433
 Resolves: rhbz#1138267
 Resolves: rhbz#1147498
 Resolves: rhbz#1138581
 Resolves: rhbz#1142122
 Resolves: rhbz#1094548
 Resolves: rhbz#1144448");

  script_tag(name:"affected", value:"'sudo' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.6p3~19.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.6p3~19.el6", rls:"OracleLinux6"))) {
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
