# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2024.5809");
  script_cve_id("CVE-2024-50340", "CVE-2024-50342", "CVE-2024-50343", "CVE-2024-50345");
  script_tag(name:"creation_date", value:"2024-11-12 04:08:52 +0000 (Tue, 12 Nov 2024)");
  script_version("2025-09-05T05:38:20+0000");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-04 16:09:49 +0000 (Thu, 04 Sep 2025)");

  script_name("Debian: Security Advisory (DSA-5809-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5809-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2024/DSA-5809-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DSA-5809-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-all-my-sms-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-amazon-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-amazon-sns-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-amazon-sqs-messenger", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-amqp-messenger", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-asset", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-beanstalkd-messenger", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-cache", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-clickatell-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-crowdin-translation-provider", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug-bundle", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-discord-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-messenger", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dotenv", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-error-handler", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-esendex-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-expo-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-expression-language", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-fake-chat-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-fake-sms-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-firebase-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-free-mobile-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-gateway-api-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-gitter-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-google-chat-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-google-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-client", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-inflector", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-infobip-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-iqsms-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-ldap", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-light-sms-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-linked-in-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-lock", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-loco-translation-provider", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-lokalise-translation-provider", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mailchimp-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mailgun-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mailjet-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mailjet-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mattermost-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mercure-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-message-bird-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-message-media-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-messenger", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-microsoft-teams-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mime", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-mobyt-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-nexmo-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-octopush-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-oh-my-smtp-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-one-signal-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-ovh-cloud-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-password-hasher", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-phpunit-bridge", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-postmark-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-info", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-rate-limiter", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-redis-messenger", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-rocket-chat-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-runtime", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-core", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-csrf", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-guard", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-http", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-semaphore", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-sendgrid-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-sendinblue-mailer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-sendinblue-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-sinch-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-slack-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-sms-biuras-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-sms77-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-smsapi-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-smsc-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-spot-hit-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-string", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-telegram-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-telnyx-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-turbo-sms-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twilio-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-uid", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-var-dumper", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-var-exporter", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-vonage-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-link", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-workflow", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yunpian-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-zulip-notifier", ver:"5.4.23+dfsg-1+deb12u3", rls:"DEB12"))) {
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
