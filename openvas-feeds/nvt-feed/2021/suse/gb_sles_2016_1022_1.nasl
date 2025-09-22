# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1022.1");
  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-13 13:58:43 +0000 (Wed, 13 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1022-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1022-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161022-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/320709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974629");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-April/001997.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2016:1022-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Samba was updated to the 4.2.x codestream, bringing some new features and security fixes (bsc#973832, FATE#320709).

These security issues were fixed:
- CVE-2015-5370: DCERPC server and client were vulnerable to DOS and MITM attacks (bsc#936862).
- CVE-2016-2110: A man-in-the-middle could have downgraded NTLMSSP authentication (bsc#973031).
- CVE-2016-2111: Domain controller netlogon member computer could have been spoofed (bsc#973032).
- CVE-2016-2112: LDAP conenctions were vulnerable to downgrade and MITM attack (bsc#973033).
- CVE-2016-2113: TLS certificate validation were missing (bsc#973034).
- CVE-2016-2115: Named pipe IPC were vulnerable to MITM attacks (bsc#973036).
- CVE-2016-2118: 'Badlock' DCERPC impersonation of authenticated account were possible (bsc#971965).

Also the following fixes were done:
- Upgrade on-disk FSRVP server state to new version, (bsc#924519).
- Fix samba.tests.messaging test and prevent potential tdb corruption by removing obsolete now invalid tdb_close call, (bsc#974629).
- Align fsrvp feature sources with upstream version.
- Obsolete libsmbsharemodes0 from samba-libs and libsmbsharemodes-devel from samba-core-devel, (bsc#973832).
- s3:utils/smbget: Fix recursive download, (bso#6482).
- s3: smbd: posix_acls: Fix check for setting u:g:o entry on a filesystem with no ACL support, (bso#10489).
- docs: Add example for domain logins to smbspool man page, (bso#11643).
- s3-client: Add a KRB5 wrapper for smbspool, (bso#11690).
- loadparm: Fix memory leak issue, (bso#11708).
- lib/tsocket: Work around sockets not supporting FIONREAD, (bso#11714).
- ctdb-scripts: Drop use of 'smbcontrol winbindd ip-dropped ...', (bso#11719).
- s3:smbd:open: Skip redundant call to file_set_dosmode when creating a new file, (bso#11727).
- param: Fix str_list_v3 to accept ',' again, (bso#11732).
- Real memeory leak(buildup) issue in loadparm, (bso#11740).
- Obsolete libsmbclient from libsmbclient0 and libpdb-devel from libsamba-passdb-devel while not providing it, (bsc#972197).
- Getting and setting Windows ACLs on symlinks can change permissions on link
- Only obsolete but do not provide gplv2/3 package names, (bsc#968973).
- Enable clustering (CTDB) support, (bsc#966271).
- s3: smbd: Fix timestamp rounding inside SMB2 create, (bso#11703), (bsc#964023).
- vfs_fruit: Fix renaming directories with open files, (bso#11065).
- Fix MacOS finder error 36 when copying folder to Samba, (bso#11347).
- s3:smbd/oplock: Obey kernel oplock setting when releasing oplocks, (bso#11400).
- Fix copying files with vfs_fruit when using vfs_streams_xattr without stream prefix and type suffix, (bso#11466).
- s3:libsmb: Correctly initialize the list head when keeping a list of primary followed by DFS connections, (bso#11624).
- Reduce the memory footprint of empty string options, (bso#11625).
- lib/async_req: Do not install async_connect_send_test, (bso#11639).
- docs: Fix typos in man ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0-32bit", rpm:"libgensec0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgensec0", rpm:"libgensec0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libregistry0", rpm:"libregistry0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit", rpm:"libsamba-passdb0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0", rpm:"libsamba-passdb0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0-32bit", rpm:"libsmbclient-raw0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-raw0", rpm:"libsmbclient-raw0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-32bit", rpm:"libsmbclient0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-32bit", rpm:"libsmbldap0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0", rpm:"libsmbldap0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-32bit", rpm:"samba-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.2.4~18.17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.2.4~18.17.1", rls:"SLES12.0"))) {
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
