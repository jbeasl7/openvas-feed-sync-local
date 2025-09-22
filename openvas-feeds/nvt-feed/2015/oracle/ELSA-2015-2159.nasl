# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122761");
  script_cve_id("CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143", "CVE-2015-3148");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:33 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-2159)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2159");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2159.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the ELSA-2015-2159 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7.29.0-25.0.1]
- disable check to make build pass

[7.29.0-25]
- fix spurious failure of test 1500 on ppc64le (#1218272)

[7.29.0-24]
- use the default min/max TLS version provided by NSS (#1170339)
- improve handling of timeouts and blocking direction to speed up FTP (#1218272)

[7.29.0-23]
- require credentials to match for NTLM re-use (CVE-2015-3143)
- close Negotiate connections when done (CVE-2015-3148)

[7.29.0-22]
- reject CRLFs in URLs passed to proxy (CVE-2014-8150)

[7.29.0-21]
- use only full matches for hosts used as IP address in cookies (CVE-2014-3613)
- fix handling of CURLOPT_COPYPOSTFIELDS in curl_easy_duphandle (CVE-2014-3707)

[7.29.0-20]
- eliminate unnecessary delay when resolving host from /etc/hosts (#1130239)
- allow to enable/disable new AES cipher-suites (#1066065)
- call PR_Cleanup() on curl tool exit if NSPR is used (#1071254)
- implement non-blocking TLS handshake (#1091429)
- fix limited connection re-use for unencrypted HTTP (#1101092)
- disable libcurl-level downgrade to SSLv3 (#1154060)
- include response headers added by proxy in CURLINFO_HEADER_SIZE (#1161182)
- ignore CURLOPT_FORBID_REUSE during NTLM HTTP auth (#1166264)");

  script_tag(name:"affected", value:"'curl' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~25.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~25.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~25.0.1.el7", rls:"OracleLinux7"))) {
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
