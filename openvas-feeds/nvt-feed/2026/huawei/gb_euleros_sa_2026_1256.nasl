# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1256");
  script_cve_id("CVE-2024-5642", "CVE-2025-12084", "CVE-2025-13836", "CVE-2025-13837", "CVE-2025-6075", "CVE-2025-8291");
  script_tag(name:"creation_date", value:"2026-03-10 04:52:39 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 19:58:12 +0000 (Tue, 10 Feb 2026)");

  script_name("Huawei EulerOS: Security Advisory for python3 (EulerOS-SA-2026-1256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1256");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1256");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python3' package(s) announced via the EulerOS-SA-2026-1256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"If the value passed to os.path.expandvars() is user-controlled a performance degradation is possible when expanding environment variables.(CVE-2025-6075)

When reading an HTTP response from a server, if no read amount is specified, the default behavior will be to use Content-Length. This allows a malicious server to cause the client to read large amounts of data into memory, potentially causing OOM or other DoS.(CVE-2025-13836)

When building nested elements using xml.dom.minidom methods such as appendChild() that have a dependency on _clear_id_cache() the algorithm is quadratic. Availability can be impacted when building excessively nested documents.(CVE-2025-12084)

The 'zipfile' module would not check the validity of the ZIP64 End of Central Directory (EOCD) Locator record offset value would not be used to locate the ZIP64 EOCD record, instead the ZIP64 EOCD record would be assumed to be the previous record in the ZIP archive. This could be abused to create ZIP archives that are handled differently by the 'zipfile' module compared to other ZIP implementations.Remediation maintains this behavior, but checks that the offset specified in the ZIP64 EOCD Locator record matches the expected value.(CVE-2025-8291)

CPython 3.9 and earlier doesn't disallow configuring an empty list ('[]') for SSLContext.set_npn_protocols() which is an invalid value for the underlying OpenSSL API. This results in a buffer over-read when NPN is used (see CVE-2024-5535 for OpenSSL). This vulnerability is of low severity due to NPN being not widely used and specifying an empty list likely being uncommon in-practice (typically a protocol name would be configured).(CVE-2024-5642)

When loading a plist file, the plistlib module reads data in size specified by the file itself, meaning a malicious file can cause OOM and DoS issues(CVE-2025-13837)");

  script_tag(name:"affected", value:"'python3' package(s) on Huawei EulerOS V2.0SP13(x86_64).");

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

if(release == "EULEROS-2.0SP13-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.9.9~28.h20.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fgo", rpm:"python3-fgo~3.9.9~28.h20.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unversioned-command", rpm:"python3-unversioned-command~3.9.9~28.h20.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
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
