# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0319.1");
  script_cve_id("CVE-2022-27191", "CVE-2022-28948", "CVE-2023-28452", "CVE-2023-30464", "CVE-2024-0874", "CVE-2024-22189");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-26 18:37:16 +0000 (Thu, 26 Sep 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0319-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0319-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2JLUFKCHWHJJ2MQ6XRREF7D4OOWB23V2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coredns' package(s) announced via the openSUSE-SU-2024:0319-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for coredns fixes the following issues:

Update to version 1.11.3:

 * optimize the performance for high qps (#6767)
 * bump deps
 * Fix zone parser error handling (#6680)
 * Add alternate option to forward plugin (#6681)
 * fix: plugin/file: return error when parsing the file fails (#6699)
 * [fix:documentation] Clarify autopath README (#6750)
 * Fix outdated test (#6747)
 * Bump go version from 1.21.8 to 1.21.11 (#6755)
 * Generate zplugin.go correctly with third-party plugins (#6692)
 * dnstap: uses pointer receiver for small response writer (#6644)
 * chore: fix function name in comment (#6608)
 * [plugin/forward] Strip local zone from IPV6 nameservers (#6635)
- fixes CVE-2023-30464
- fixes CVE-2023-28452

Update to upstream head (git commit #5a52707):

 * bump deps to address security issue CVE-2024-22189
 * Return RcodeServerFailure when DNS64 has no next plugin (#6590)
 * add plusserver to adopters (#6565)
 * Change the log flags to be a variable that can be set prior to calling Run (#6546)
 * Enable Prometheus native histograms (#6524)
 * forward: respect context (#6483)
 * add client labels to k8s plugin metadata (#6475)
 * fix broken link in webpage (#6488)
 * Repo controlled Go version (#6526)
 * removed the mutex locks with atomic bool (#6525)

Update to version 1.11.2:

 * rewrite: fix multi request concurrency issue in cname rewrite (#6407)
 * plugin/tls: respect the path specified by root plugin (#6138)
 * plugin/auto: warn when auto is unable to read elements of the directory tree (#6333)
 * fix: make the codeowners link relative (#6397)
 * plugin/etcd: the etcd client adds the DialKeepAliveTime parameter (#6351)
 * plugin/cache: key cache on Checking Disabled (CD) bit (#6354)
 * Use the correct root domain name in the proxy plugin's TestHealthX tests (#6395)
 * Add PITS Global Data Recovery Services as an adopter (#6304)
 * Handle UDP responses that overflow with TC bit with test case (#6277)
 * plugin/rewrite: add rcode as a rewrite option (#6204)

- CVE-2024-0874: coredns: CD bit response is cached and served later

- Update to version 1.11.1:

 * Revert 'plugin/forward: Continue waiting after receiving malformed responses
 * plugin/dnstap: add support for 'extra' field in payload
 * plugin/cache: fix keepttl parsing

- Update to version 1.11.0:

 * Adds support for accepting DNS connections over QUIC (doq).
 * Adds CNAME target rewrites to the rewrite plugin.
 * Plus many bug fixes, and some security improvements.
 * This release introduces the following backward incompatible changes:
 + In the kubernetes plugin, we have dropped support for watching Endpoint and Endpointslice v1beta,
 since all supported K8s versions now use Endpointslice.
 + The bufsize plugin changed its default size limit value to 1232
 + Some changes to forward plugin metrics.

- Update to version 1.10.1:

 * Corrected architecture labels in multi-arch image manifest
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'coredns' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"coredns", rpm:"coredns~1.11.3~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coredns-extras", rpm:"coredns-extras~1.11.3~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
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
