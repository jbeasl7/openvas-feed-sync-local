# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123587");
  script_cve_id("CVE-2013-0791", "CVE-2013-1620");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1144)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1144");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1144.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss, nss-softokn, nss-util' package(s) announced via the ELSA-2013-1144 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nspr
[4.9.5-2]
- Update to NSPR_4_9_5_RTM
- Resolves: rhbz#927186 - Rebase to nspr-4.9.5
- Add upstream URL for an existing patch per packaging guidelines

[4.9.5-1]
- Resolves: Rebase to nspr-4.9.5

[4.9.2-1]
- Update to nspr-4.9.2
- Related: rhbz#863286

nss
[3.14.3-4.0.1.el6_4]
- Added nss-vendor.patch to change vendor

[3.14.3-4]
- Revert to accepting MD5 on digital signatures by default
- Resolves: rhbz#957603 - nss 3.14 - MD5 hash algorithm disabled

[3.14.3-3]
- Ensure pem uses system freebl as with this update freebl brings in new API's
- Resolves: rhbz#927157 - [RFE][RHEL6] Rebase to nss-3.14.3 to fix the lucky-13 issue

[3.14.3-2]
- Install sechash.h and secmodt.h which are now provided by nss-devel
- Resolves: rhbz#927157 - [RFE][RHEL6] Rebase to nss-3.14.3 to fix the lucky-13 issue
- Remove unsafe -r option from commands that remove headers already shipped by nss-util and nss-softoken

[3.14.3-1]
- Update to NSS_3.14.3_RTM
- Resolves: rhbz#927157 - [RFE][RHEL6] Rebase to nss-3.14.3 to fix the lucky-13 issue
- Update expired test certificates (fixed in upstream bug 852781)
- Sync up pem module's rsawrapr.c with softoken's upstream changes for nss-3.14.3
- Reactivate the aia tests

nss-softokn
[3.14.3-3]
- Add patch to conditionally compile according to old or new sqlite api
- new is used on rhel-6 while rhel-5 uses old but we need the same code for both
- Resolves: rhbz#927158 - Rebase to nss-softokn 3.14.3 to fix the lucky-13 issue

[3.14.3-2]
- Revert to using a code patch for relro support
- Related: rhbz#927158

[3.14.3-1]
- Update to NSS_3_14_3_RTM
- Resolves: rhbz#927158 - Rebase to nss-softokn 3.14.3 to fix the lucky-13 issue
- Add export LD_LIBRARY_PATH=//usr/lib before the signing commands in __spec_install_post scriplet
to ensure signing tool links with in-tree freebl so verification uses same algorithm as in signing
- Add %check section to run the upstream crypto reqression test suite as per packaging guidelines
- Don't install sechash.h or secmodt.h which as per 3.14 are provided by nss-devel
- Update the licence to MPLv2.0

[3.12.9-12]
- Bootstrapping of the builroot in preparation for rebase to 3.14.3
- Remove hasht.h from the %files devel list to prevent update conflicts with nss-util
- With 3.14.3 hasht.h will be provided by nss-util-devel
- Related: rhbz#927158 - rebase nss-softokn to 3.14.3

nss-util
[3.14.3-3]
- Resolves: rhbz#984967 - nssutil_ReadSecmodDB leaks memory

[3.14.3-2]
- Revert to accepting MD5 on digital signatures by default
- Resolves: rhbz#957603 - nss 3.14 - MD5 hash algorithm disabled

[3.14.3-1]
- Update to NSS_3_14_3_RTM
- Resolves: rhbz#927171 - Rebase to 3.14.3 as part of the fix for the lucky-13 issue");

  script_tag(name:"affected", value:"'nspr, nss, nss-softokn, nss-util' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9.5~2.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9.5~2.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.14.3~4.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.14.3~4.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.14.3~4.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.14.3~3.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-devel", rpm:"nss-softokn-devel~3.14.3~3.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.14.3~3.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-freebl-devel", rpm:"nss-softokn-freebl-devel~3.14.3~3.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.14.3~4.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.14.3~4.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.14.3~3.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.14.3~3.el6_4", rls:"OracleLinux6"))) {
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
