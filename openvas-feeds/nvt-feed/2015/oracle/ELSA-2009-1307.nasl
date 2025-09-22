# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122447");
  script_cve_id("CVE-2008-5188");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:32 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1307");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1307.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ecryptfs-utils' package(s) announced via the ELSA-2009-1307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[75-4]
- fix EOF handling (#499367)
- add icon to gui desktop file

[75-3]
- ask for password confirmation when creating openssl key (#500850)
- removed executable permission from ecryptfs-dot-private (#500817)
- ecryptfs-rewrite-file: improve of progress output (#500813)
- don't error out when unwrapping and adding a key that already exists (#500810)
- fix typo in ecryptfs-rewrite-file(1) (#500804)
- add error message about full keyring (#501460)
- gui sub-package must requires pygtk2-libglade (#500997)
- require cryptsetup-luks for encrypted swap (#500824)
- use blkid instead of vol_id (#500820)
- don't rely on cryptdisks service (#500829)

[75-2]
- don't hang when used with wrong/missing stdin (#499367)
- don't print error when key already removed (#499167)
- refuse mounting with too small rsa key (#499175)
- don't error out when adding key that already exists (#500361)
- allow only working key sizes (#500352)
- return nonzero when fnek is not supported (#500566)
- add icon for Access-Your-Private-Data.desktop file (#500623)
- fix information about openssl_passwd in openssl_passwd_file (#499128)
- don't list mount.ecryptfs_private twice

[75-1]
- update to 75 and drop some patches

[74-24]
- add suid mount.ecryptfs_private, restrict it to ecryptfs group

[74-23]
- skip releases -2 - -22 to be sure its always newer nvr

[74-22]
- drop setuid for mount.ecryptfs_private
- resolves: #482834

[74-1]
- update to 74
- fix difference between apps. real names and names in usage messages (#475969)
- describe verobse and verbosity=X in man page (#470444)
- adding passphrase to keyring is fixed (#469662)
- mount won't fail with wrong/empty input to yes/no questions (#466210)
- try to load modules instead of failing when its missing (#460496)
- fix wrong return codes (#479429)
- resolves: #482834");

  script_tag(name:"affected", value:"'ecryptfs-utils' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils", rpm:"ecryptfs-utils~75~5.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils-devel", rpm:"ecryptfs-utils-devel~75~5.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils-gui", rpm:"ecryptfs-utils-gui~75~5.el5", rls:"OracleLinux5"))) {
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
