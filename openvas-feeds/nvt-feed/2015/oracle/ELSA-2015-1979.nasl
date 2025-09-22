# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122729");
  script_cve_id("CVE-2015-3240");
  script_tag(name:"creation_date", value:"2015-11-08 11:05:19 +0000 (Sun, 08 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-1979)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1979");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1979.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreswan' package(s) announced via the ELSA-2015-1979 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.15-5.0.1]
- add libreswan-oracle.patch to detect Oracle Linux distro

[3.15-5]
- Resolves: rhbz#1273719 libreswan FIPS test mistakenly looks for non-existent file hashes

[3.15-4]
- Resolves: rhbz#1268775 libreswan should support strictcrlpolicy alias
- Resolves: rhbz#1268776 Pluto crashes after stop when I use floating ip address
- Resolves: rhbz#1268773 Pluto crashes on INITIATOR site during 'service ipsec stop'
- Resolves: rhbz#1208022 libreswan ignores module blacklist rules
- Resolves: rhbz#1270673 ipsec does not work properly on loopback

[3.15-2]
- Resolves: rhbz#1259208 CVE-2015-3240
- Merge rhel6 and rhel7 spec into one
- Be lenient for racoon padding behaviour
- Fix seedev option to /dev/random
- Some IKEv1 PAM methods always gave 'Permission denied'
- Parser workarounds for differences in gcc/flex/bison on rhel6/rhel7
- Parser fix to allow specifying time without unit (openswan compat)
- Fix Labeled IPsec on rekeyed IPsec SA's
- Workaround for wrong padding by racoon2
- Disable NSS HW GCM to workaround rhel6 xen builders bug");

  script_tag(name:"affected", value:"'libreswan' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~3.15~5.0.1.el7_1", rls:"OracleLinux7"))) {
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
