# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1576.1");
  script_cve_id("CVE-2013-7038", "CVE-2013-7039");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1576-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171576-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854443");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002945.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmicrohttpd' package(s) announced via the SUSE-SU-2017:1576-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libmicrohttpd fixes the following issues:

- CVE-2013-7038: The MHD_http_unescape function in libmicrohttpd might
 have allowed remote attackers to obtain sensitive information or cause
 a denial of service (crash) via unspecified vectors that trigger an
 out-of-bounds read. (bsc#854443)
- CVE-2013-7039: Stack-based buffer overflow in the MHD_digest_auth_check
 function in libmicrohttpd, when MHD_OPTION_CONNECTION_MEMORY_LIMIT is
 set to a large value, allowed remote attackers to cause a denial of
 service (crash) or possibly execute arbitrary code via a long URI in an
 authentication header. (bsc#854443)

- Fixed various bugs found during a 2017 audit, which are more hardening
 measures and not security issues. (bsc#1041216)");

  script_tag(name:"affected", value:"'libmicrohttpd' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libmicrohttpd10", rpm:"libmicrohttpd10~0.9.30~5.1", rls:"SLES12.0SP2"))) {
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
