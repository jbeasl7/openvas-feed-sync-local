# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131298");
  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:01 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-13 13:58:43 +0000 (Wed, 13 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0151");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0151.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2950-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18194");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2015-5370.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2110.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2111.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2112.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2115.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2118.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the MGASA-2016-0151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated samba packages fix security vulnerability:

Jouni Knuutinen discovered that Samba contained multiple flaws in the
DCE/RPC implementation. A remote attacker could use this issue to perform
a denial of service, downgrade secure connections by performing a man in
the middle attack, or possibly execute arbitrary code (CVE-2015-5370).

Stefan Metzmacher discovered that Samba contained multiple flaws in the
NTLMSSP authentication implementation. A remote attacker could use this
issue to downgrade connections to plain text by performing a man in the
middle attack (CVE-2016-2110).

Alberto Solino discovered that a Samba domain controller would establish a
secure connection to a server with a spoofed computer name. A remote
attacker could use this issue to obtain sensitive information
(CVE-2016-2111).

Stefan Metzmacher discovered that the Samba LDAP implementation did not
enforce integrity protection. A remote attacker could use this issue to
hijack LDAP connections by performing a man in the middle attack
(CVE-2016-2112).

Stefan Metzmacher discovered that Samba did not enable integrity protection
for IPC traffic. A remote attacker could use this issue to perform a man in
the middle attack (CVE-2016-2115).

Stefan Metzmacher discovered that Samba incorrectly handled the MS-SAMR and
MS-LSAD protocols. A remote attacker could use this flaw with a man in the
middle attack to impersonate users and obtain sensitive information from
the Security Account Manager database. This flaw is known as Badlock
(CVE-2016-2118).");

  script_tag(name:"affected", value:"'samba' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-virusfilter-clamav", rpm:"samba-virusfilter-clamav~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-virusfilter-fsecure", rpm:"samba-virusfilter-fsecure~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-virusfilter-sophos", rpm:"samba-virusfilter-sophos~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.25~2.3.mga5", rls:"MAGEIA5"))) {
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
