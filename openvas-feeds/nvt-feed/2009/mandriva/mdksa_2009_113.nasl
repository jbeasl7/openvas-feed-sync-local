# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64130");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2009-0688");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:113 (cyrus-sasl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|3\.0|4\.0|2\.0)");
  script_tag(name:"insight", value:"Multiple buffer overflows in the CMU Cyrus SASL library before 2.1.23
might allow remote attackers to execute arbitrary code or cause a
denial of service application crash) via strings that are used as
input to the sasl_encode64 function in lib/saslutil.c (CVE-2009-0688).

The updated packages have been patched to prevent this.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:113");
  script_tag(name:"summary", value:"The remote host is missing an update to cyrus-sasl
announced via advisory MDVSA-2009:113.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~27.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~29.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~34.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-srp", rpm:"libsasl2-plug-srp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-srp", rpm:"lib64sasl2-plug-srp~2.1.15~10.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~11.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-srp", rpm:"libsasl2-plug-srp~2.1.15~10.6.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
