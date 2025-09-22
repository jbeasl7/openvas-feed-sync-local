# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123522");
  script_cve_id("CVE-2012-4453");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:01 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-1674)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1674");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1674.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dracut' package(s) announced via the ELSA-2013-1674 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[004-336.0.1]
- do not strip modules with signatures. [orabug 17458249] (Jerry Snitselaar)
- scsi_wait module removed in 3.8. Mute errors. [orabug 16977193] (Maxim Uvarov)
 find firmware in /lib/modules/firmware/2.6.32-400.1.1.el5uek first
 and /lib/modules/firmware second ( Resolves: Orabug: 13351090
- Fix btrfs discovery [orabug 13388545]
 [004-336]
- install /etc/system-fips in the initramfs
Resolves: rhbz#1012626
 [004-335]
- fixed interface renaming
Resolves: rhbz#1019104
 [004-334]
- fcoe: add --link-retry=100 to fipvlan call
Resolves: rhbz#1012316
- ldd: redirect error to /dev/null
- do not turn off biosdevname, if not given on kernel cmdline
Resolves: rhbz#1011508
- network: fixed ibft parsing
Resolves: rhbz#1011508
 [004-330]
- changed /etc/redhat-fips to /etc/system-fips
Resolves: rhbz#1012626
 [004-329]
- add /etc/redhat-fips
Resolves: rhbz#1012626
 [004-328]
- fixed crypt: add support for keyfiles in the initramfs
Resolves: rhbz#886194
 [004-327]
- fixed crypt: add support for keyfiles in the initramfs
Resolves: rhbz#886194
- fixed booting with iSCSI and without network config
Resolves: rhbz#910605
 [004-322]
- fixed crypt: add support for keyfiles in the initramfs
Resolves: rhbz#886194
- fixed FIPS module checking
Resolves: rhbz#947729
 [004-316]
- create the initramfs non-world readable
- unset LD_LIBRARY_PATH and GREP_OPTIONS
Resolves: rhbz#912299
- add mkinitrd man page
Resolves: rhbz#610462
- add bonding
Resolves: rhbz#851666
- lvm: add '--yes' to lvchange
Resolves: rhbz#720684
- crypt: add support for keyfiles in the initramfs
Resolves: rhbz#886194
- start iscsi regardless of network, if requested
Resolves: rhbz#813687
- install multipath module only, when root is multipath in generic mode
Resolves: rhbz#916144
- fips: handle checksum checks for RHEV kernels
Resolves: rhbz#947729
- add xhci-hcd driver
Resolves: rhbz#960729");

  script_tag(name:"affected", value:"'dracut' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dracut", rpm:"dracut~004~336.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-caps", rpm:"dracut-caps~004~336.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-fips", rpm:"dracut-fips~004~336.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-fips-aesni", rpm:"dracut-fips-aesni~004~336.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-generic", rpm:"dracut-generic~004~336.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-kernel", rpm:"dracut-kernel~004~336.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-network", rpm:"dracut-network~004~336.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-tools", rpm:"dracut-tools~004~336.0.1.el6", rls:"OracleLinux6"))) {
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
