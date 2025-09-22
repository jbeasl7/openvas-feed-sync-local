# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0386.1");
  script_cve_id("CVE-2012-6150", "CVE-2013-0213", "CVE-2013-0214", "CVE-2013-4124", "CVE-2013-4408", "CVE-2013-4475", "CVE-2013-4496", "CVE-2014-0178", "CVE-2014-0244", "CVE-2014-3493", "CVE-2015-0240");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0386-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150386-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/437293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/726937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/765270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/769957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/770056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/770262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/771516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/779269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/783384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/783719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/786350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/786677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/787983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/788159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/790741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/791183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/792294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/792340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/798856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/807334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/817880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/838472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/844307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/844720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/872396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/872912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917376");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001256.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Samba' package(s) announced via the SUSE-SU-2015:0386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues with Samba:

 * bnc#844720: DCERPC frag_len not checked (CVE-2013-4408)
 * bnc#853347: winbind pam security problem (CVE-2012-6150)
 * bnc#848101: No access check verification on stream files
 (CVE-2013-4475)

And fixes the following non-security issues:

 * bnc#853021: libsmbclient0 package description contains comments
 * bnc#817880: rpcclient adddriver and setdrive do not set all needed
 registry entries
 * bnc#838472: Client trying to delete print job fails: Samba returns:
 WERR_INVALID_PRINTER_NAME
 * bnc#854520 and bnc#849226: various upstream fixes

Security Issue references:

 * CVE-2012-6150
 <[link moved to references]>
 * CVE-2013-4408
 <[link moved to references]>
 * CVE-2013-4475
 <[link moved to references]>");

  script_tag(name:"affected", value:"'Samba' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server for SAP Applications 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ldapsmb", rpm:"ldapsmb~1.34b~12.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb1", rpm:"libldb1~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-32bit", rpm:"libsmbclient0-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-x86", rpm:"libsmbclient0-x86~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc1", rpm:"libtalloc1~3.4.3~1.50.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc1-32bit", rpm:"libtalloc1-32bit~3.4.3~1.50.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc1-x86", rpm:"libtalloc1-x86~3.4.3~1.50.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc2", rpm:"libtalloc2~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc2-32bit", rpm:"libtalloc2-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc2-x86", rpm:"libtalloc2-x86~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb1-32bit", rpm:"libtdb1-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb1-x86", rpm:"libtdb1-x86~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent0", rpm:"libtevent0~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent0-32bit", rpm:"libtevent0-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-x86", rpm:"libwbclient0-x86~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-32bit", rpm:"samba-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-x86", rpm:"samba-client-x86~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb-printing", rpm:"samba-krb-printing~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-x86", rpm:"samba-winbind-x86~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-x86", rpm:"samba-x86~3.6.3~0.33.39.1", rls:"SLES11.0SP2"))) {
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
