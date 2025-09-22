# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0636.1");
  script_cve_id("CVE-2015-5041", "CVE-2015-7575", "CVE-2015-7981", "CVE-2015-8126", "CVE-2015-8472", "CVE-2015-8540", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-07 13:55:29 +0000 (Tue, 07 Jun 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0636-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0636-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160636-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963937");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-March/001910.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-ibm' package(s) announced via the SUSE-SU-2016:0636-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-ibm fixes the following issues by updating to 7.0-9.30 (bsc#963937):

- CVE-2015-5041: Could could have invoked non-public interface methods under certain circumstances
- CVE-2015-7575: The TLS protocol could allow weaker than expected security caused by a collision attack when using the MD5 hash function for signing a ServerKeyExchange message during a TLS handshake. An attacker could exploit this vulnerability using man-in-the-middle techniques to impersonate a TLS server and obtain credentials
- CVE-2015-7981: libpng could allow a remote attacker to obtain sensitive information, caused by an out-of-bounds read in the png_convert_to_rfc1123 function. An attacker could exploit this vulnerability to obtain sensitive information
- CVE-2015-8126: buffer overflow in libpng caused by improper bounds checking by the png_set_PLTE() and png_get_PLTE() functions
- CVE-2015-8472: buffer overflow in libpng caused by improper bounds checking by the png_set_PLTE() and png_get_PLTE() functions
- CVE-2015-8540: libpng is vulnerable to a buffer overflow, caused by a read underflow in png_check_keyword in pngwutil.c. By sending an overly long argument, a remote attacker could overflow a buffer and execute arbitrary code on the system or cause the application to crash.
- CVE-2016-0402: An unspecified vulnerability related to the Networking component has no confidentiality impact, partial integrity impact, and no availability impact
- CVE-2016-0448: An unspecified vulnerability related to the JMX component could allow a remote attacker to obtain sensitive information
- CVE-2016-0466: An unspecified vulnerability related to the JAXP component could allow a remote attacker to cause a denial of service
- CVE-2016-0483: An unspecified vulnerability related to the AWT component has complete confidentiality impact, complete integrity impact, and complete availability impact
- CVE-2016-0494: An unspecified vulnerability related to the 2D component has complete confidentiality impact, complete integrity impact, and complete availability impact

The following bugs were fixed:

- bsc#960402: resolve package conflicts in devel package");

  script_tag(name:"affected", value:"'java-1_7_0-ibm' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr9.30~47.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr9.30~47.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr9.30~47.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr9.30~47.1", rls:"SLES11.0SP3"))) {
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
