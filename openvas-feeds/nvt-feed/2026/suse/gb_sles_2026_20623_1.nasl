# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20623.1");
  script_cve_id("CVE-2025-47912", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58186", "CVE-2025-58187", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61724", "CVE-2025-61725", "CVE-2025-61726", "CVE-2025-61727", "CVE-2025-61728", "CVE-2025-61729", "CVE-2025-61730", "CVE-2025-61731", "CVE-2025-68119", "CVE-2025-68121");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 16:08:03 +0000 (Tue, 10 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20623-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20623-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620623-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257486");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024649.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.25-openssl' package(s) announced via the SUSE-SU-2026:20623-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.25-openssl fixes the following issues:

- Update to version 1.25.7 (jsc#SLE-18320)
- CVE-2025-61730: crypto/tls: handshake messages may be processed at the incorrect encryption level (bsc#1256821)
- CVE-2025-68119: cmd/go: unexpected code execution when invoking toolchain (bsc#1256820)
- CVE-2025-61731: cmd/go: bypass of flag sanitization can lead to arbitrary code execution (bsc#1256819)
- CVE-2025-61726: net/http: memory exhaustion in Request.ParseForm (bsc#1256817)
- CVE-2025-61728: archive/zip: denial of service when parsing arbitrary ZIP archives (bsc#1256816)
- CVE-2025-68121: crypto/tls: Config.Clone copies automatically generated session ticket keys, session resumption does not account for the expiration of full certificate chain (bsc#1256818)
- CVE-2025-61729: crypto/x509: excessive resource consumption in printing error string for host certificate validation (bsc#1254431)
- CVE-2025-61727: crypto/x509: excluded subdomain constraint doesn't preclude wildcard SA (bsc#1254430)
- CVE-2025-58189: crypto/tls: ALPN negotiation error contains attacker controlled information (bsc#1251255)
- CVE-2025-61725: net/mail: excessive CPU consumption in ParseAddress (bsc#1251253)
- CVE-2025-58188: crypto/x509: panic when validating certificates with DSA public keys (bsc#1251260)
- CVE-2025-58185: encoding/asn1: pre-allocating memory when parsing DER payload can cause memory exhaustion (bsc#1251258)
- CVE-2025-58186: net/http: lack of limit when parsing cookies can cause memory exhaustion (bsc#1251259)
- CVE-2025-61723: encoding/pem: quadratic complexity when parsing some invalid inputs (bsc#1251256)
- CVE-2025-58183: archive/tar: unbounded allocation when parsing GNU sparse map (bsc#1251261)
- CVE-2025-47912: net/url: insufficient validation of bracketed IPv6 hostnames (bsc#1251257)
- CVE-2025-58187: crypto/x509: quadratic complexity when checking name constraints (bsc#1251254)
- CVE-2025-61724: net/textproto: excessive CPU consumption in Reader.ReadResponse (bsc#1251262)");

  script_tag(name:"affected", value:"'go1.25-openssl' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl", rpm:"go1.25-openssl~1.25.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-doc", rpm:"go1.25-openssl-doc~1.25.7~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-race", rpm:"go1.25-openssl-race~1.25.7~160000.1.1", rls:"SLES16.0.0"))) {
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
