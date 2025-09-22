# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882403");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-02 06:17:15 +0100 (Wed, 02 Mar 2016)");
  script_cve_id("CVE-2015-3197", "CVE-2016-0797", "CVE-2016-0800");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:21:00 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for openssl CESA-2016:0302 centos5");
  script_tag(name:"summary", value:"Check the version of openssl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the
Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1) protocols,
as well as a full-strength, general purpose cryptography library.

A padding oracle flaw was found in the Secure Sockets Layer version 2.0
(SSLv2) protocol. An attacker can potentially use this flaw to decrypt
RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol
version, allowing them to decrypt such connections. This cross-protocol
attack is publicly referred to as DROWN. (CVE-2016-0800)

Note: This issue was addressed by disabling the SSLv2 protocol by default
when using the 'SSLv23' connection methods, and removing support for weak
SSLv2 cipher suites. It is possible to re-enable the SSLv2 protocol in the
'SSLv23' connection methods by default by setting the OPENSSL_ENABLE_SSL2
environment variable before starting an application that needs to have
SSLv2 enabled. For more information, refer to the knowledge base article
linked to in the References section.

A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2
ciphers that have been disabled on the server. This could result in weak
SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to
man-in-the-middle attacks. (CVE-2015-3197)

An integer overflow flaw, leading to a NULL pointer dereference or a
heap-based memory corruption, was found in the way some BIGNUM functions of
OpenSSL were implemented. Applications that use these functions with large
untrusted input could crash or, potentially, execute arbitrary code.
(CVE-2016-0797)

Red Hat would like to thank the OpenSSL project for reporting these issues.
Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as the original
reporters of CVE-2016-0800 and CVE-2015-3197  and Guido Vranken as the
original reporter of CVE-2016-0797.

All openssl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. For the update to take
effect, all services linked to the OpenSSL library must be restarted, or
the system rebooted.");
  script_tag(name:"affected", value:"openssl on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2016:0302");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021714.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~39.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~39.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~39.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
