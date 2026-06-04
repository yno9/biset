// Release configuration — update this file for each release.
// setup.html reads this; no other file needs editing to add/update connectors.

const BISET_URLS = {
  // GitHub org — used for fallback connector download URLs.
  github_org: 'yd7a',

  // Connectors shown on the connector selection screen.
  connectors: [
    {
      id:      'biset-imap',
      label:   'External Mail',
      sub:     'IMAP & SMTP',
      checked: true,
      url:     'https://github.com/yd7a/biset/releases/latest/download/biset-imap-darwin-arm64',
    },
    {
      id:    'biset-jmap',
      label: 'Mail Server',
      sub:   'JMAP & SMTP',
    },
    {
      id:    'biset-ap',
      label: 'ActivityPub',
      sub:   'Fediverse, Mastodon',
    },
  ],

  // Interfaces shown on the interface selection screen.
  interfaces: [
    {
      id:    'biset-ui',
      label: 'biset-ui',
      sub:   'HTML interface (serverless)',
      url:   'https://raw.githubusercontent.com/yd7a/biset-core/main/index.html',
    },
    {
      id:    'biset-serve',
      label: 'Web Server',
      sub:   'Access via HTTP',
    },
  ],
}
